package auth_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/resolver/auth"
	"github.com/shigeya/dnsdata-go/types"
)

// retryAttemptTimeout is the per-attempt wait used by the retransmission
// tests: short enough to keep them fast, long enough for loopback.
const retryAttemptTimeout = 250 * time.Millisecond

// udpServer is a loopback UDP server that hands every datagram it
// receives to a handler, in order, and records the transaction IDs.
type udpServer struct {
	addr  string
	count atomic.Int32
	mu    sync.Mutex
	ids   []uint16
}

// queryIDs returns a copy of the transaction IDs received so far.
func (s *udpServer) queryIDs() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint16(nil), s.ids...)
}

// startUDPServer runs handler for each datagram received; handler gets
// the 1-based index of the datagram, the query, and a reply function.
func startUDPServer(t *testing.T, handler func(n int, query []byte, reply func([]byte))) *udpServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &udpServer{addr: conn.LocalAddr().String()}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			if len(query) >= 2 {
				s.mu.Lock()
				s.ids = append(s.ids, binary.BigEndian.Uint16(query))
				s.mu.Unlock()
			}
			idx := int(s.count.Add(1))
			handler(idx, query, func(resp []byte) { _, _ = conn.WriteTo(resp, from) })
		}
	}()
	return s
}

// startDroppingUDPServer drops the first k datagrams and answers the
// rest with an A record.
func startDroppingUDPServer(t *testing.T, k int) *udpServer {
	t.Helper()
	return startUDPServer(t, func(n int, query []byte, reply func([]byte)) {
		if n <= k {
			return
		}
		reply(buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false))
	})
}

func retryClient(attempts int, servers ...string) *auth.Client {
	return auth.NewClient(
		auth.WithServers(servers...),
		auth.WithTimeout(retryAttemptTimeout),
		auth.WithUDPAttempts(attempts),
	)
}

// Fewer drops than attempts: the same server answers a retransmission.
func TestClient_UDPRetransmit_SucceedsWhenDropsBelowAttempts(t *testing.T) {
	const attempts = 3
	for k := 0; k < attempts; k++ {
		srv := startDroppingUDPServer(t, k)
		resp, err := retryClient(attempts, srv.addr).Query(context.Background(), "example.com.", types.TypeA)
		if err != nil {
			t.Fatalf("k=%d: Query: %v", k, err)
		}
		if len(resp) < 12 {
			t.Fatalf("k=%d: response too short", k)
		}
		if got := int(srv.count.Load()); got != k+1 {
			t.Errorf("k=%d: server received %d datagrams, want %d", k, got, k+1)
		}
	}
}

// As many drops as attempts: the client gives up on that server and
// moves to the next one.
func TestClient_UDPRetransmit_MovesToNextServerAfterAttempts(t *testing.T) {
	const attempts = 3
	lossy := startDroppingUDPServer(t, attempts)
	good := startDroppingUDPServer(t, 0)
	if _, err := retryClient(attempts, lossy.addr, good.addr).Query(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := int(lossy.count.Load()); got != attempts {
		t.Errorf("first server received %d datagrams, want %d", got, attempts)
	}
	if got := int(good.count.Load()); got != 1 {
		t.Errorf("second server received %d datagrams, want 1", got)
	}
}

func TestClient_UDPRetransmit_AllAttemptsLost(t *testing.T) {
	const attempts = 2
	srv := startDroppingUDPServer(t, 1000)
	start := time.Now()
	_, err := retryClient(attempts, srv.addr).Query(context.Background(), "example.com.", types.TypeA)
	elapsed := time.Since(start)
	if !errors.Is(err, auth.ErrAllServersFailed) {
		t.Fatalf("err = %v, want ErrAllServersFailed", err)
	}
	if got := int(srv.count.Load()); got != attempts {
		t.Errorf("server received %d datagrams, want %d", got, attempts)
	}
	if minimum := attempts * retryAttemptTimeout; elapsed < minimum {
		t.Errorf("gave up after %v, want at least %v (attempts × timeout)", elapsed, minimum)
	}
}

// The caller's deadline bounds the whole query, retransmissions included.
func TestClient_UDPRetransmit_HonoursContextDeadline(t *testing.T) {
	srv := startDroppingUDPServer(t, 1000)
	c := auth.NewClient(
		auth.WithServers(srv.addr, srv.addr),
		auth.WithTimeout(time.Second),
		auth.WithUDPAttempts(3),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Query(ctx, "example.com.", types.TypeA)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded wrapped", err)
	}
	if elapsed > 750*time.Millisecond {
		t.Errorf("returned after %v, want close to the 250ms deadline", elapsed)
	}
	if got := int(srv.count.Load()); got != 1 {
		t.Errorf("server received %d datagrams, want 1 (no further attempt after the deadline)", got)
	}
}

// Cancelling a context without a deadline stops the wait at once.
func TestClient_UDPRetransmit_HonoursCancel(t *testing.T) {
	srv := startDroppingUDPServer(t, 1000)
	c := auth.NewClient(auth.WithServers(srv.addr), auth.WithTimeout(time.Second), auth.WithUDPAttempts(3))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.Query(ctx, "example.com.", types.TypeA)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled wrapped", err)
	}
	if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
		t.Errorf("returned after %v, want shortly after the 100ms cancel", elapsed)
	}
}

// Retransmissions reuse the transaction ID of the first query.
func TestClient_UDPRetransmit_KeepsQueryID(t *testing.T) {
	srv := startDroppingUDPServer(t, 2)
	if _, err := retryClient(3, srv.addr).Query(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
	ids := srv.queryIDs()
	if len(ids) != 3 {
		t.Fatalf("server received %d datagrams, want 3", len(ids))
	}
	for i, id := range ids[1:] {
		if id != ids[0] {
			t.Errorf("datagram %d has ID 0x%04x, first had 0x%04x", i+2, id, ids[0])
		}
	}
}

// An answer to the first transmission that arrives during the second
// attempt is accepted.
func TestClient_UDPRetransmit_AcceptsLateAnswer(t *testing.T) {
	srv := startUDPServer(t, func(n int, query []byte, reply func([]byte)) {
		if n != 1 {
			return
		}
		resp := buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 7}, false)
		time.AfterFunc(retryAttemptTimeout*3/2, func() { reply(resp) })
	})
	if _, err := retryClient(3, srv.addr).Query(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := int(srv.count.Load()); got != 2 {
		t.Errorf("server received %d datagrams, want 2", got)
	}
}

// A datagram with the wrong ID (or too short to carry one) is skipped and
// the client keeps reading for the real answer within the same attempt.
func TestClient_UDP_SkipsStrayDatagrams(t *testing.T) {
	srv := startUDPServer(t, func(_ int, query []byte, reply func([]byte)) {
		good := buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false)
		stray := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(stray, binary.BigEndian.Uint16(good)^0xFFFF)
		reply(stray)
		reply([]byte{0x01})
		reply(good)
	})
	if _, err := retryClient(1, srv.addr).Query(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
}

// When nothing but stray datagrams arrive, the timeout error still says
// an ID mismatch was seen.
func TestClient_UDP_OnlyStrayDatagramsReportsIDMismatch(t *testing.T) {
	srv := startUDPServer(t, func(_ int, query []byte, reply func([]byte)) {
		resp := buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false)
		binary.BigEndian.PutUint16(resp, binary.BigEndian.Uint16(resp)^0xFFFF)
		reply(resp)
	})
	_, err := retryClient(2, srv.addr).Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, auth.ErrIDMismatch) {
		t.Errorf("err = %v, want ErrIDMismatch wrapped", err)
	}
	if got := int(srv.count.Load()); got != 2 {
		t.Errorf("server received %d datagrams, want 2", got)
	}
}

// A wrong-ID datagram followed by a short one still reports the ID
// mismatch when no real reply comes.
func TestClient_UDP_IDMismatchSurvivesLaterShortDatagram(t *testing.T) {
	srv := startUDPServer(t, func(_ int, query []byte, reply func([]byte)) {
		resp := buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false)
		binary.BigEndian.PutUint16(resp, binary.BigEndian.Uint16(resp)^0xFFFF)
		reply(resp)
		reply([]byte{0x01})
	})
	_, err := retryClient(1, srv.addr).Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, auth.ErrIDMismatch) {
		t.Errorf("err = %v, want ErrIDMismatch wrapped", err)
	}
	if !errors.Is(err, auth.ErrResponseTooShort) {
		t.Errorf("err = %v, want ErrResponseTooShort wrapped", err)
	}
}

// A context that expires during the TCP retry after truncation is
// reported as such.
func TestClient_TCPFallback_HonoursContextDeadline(t *testing.T) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	tcpLn, err := net.Listen("tcp", udpConn.LocalAddr().String())
	if err != nil {
		t.Skipf("port collision: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		buf := make([]byte, 4096)
		n, from, err := udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := buildResponseTo(t, buf[:n], "example.com.", types.TypeA, 300, nil, true)
		_, _ = udpConn.WriteTo(resp, from)
	}()
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = conn.Close() }) // accept, never answer
	}()
	c := auth.NewClient(auth.WithServers(tcpLn.Addr().String()), auth.WithTimeout(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = c.Query(ctx, "example.com.", types.TypeA)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded wrapped", err)
	}
}

// WithUDPAttempts below 1 is raised to a single attempt.
func TestWithUDPAttempts_ClampsToOne(t *testing.T) {
	srv := startDroppingUDPServer(t, 1)
	_, err := retryClient(0, srv.addr).Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, auth.ErrAllServersFailed) {
		t.Fatalf("err = %v, want ErrAllServersFailed", err)
	}
	if got := int(srv.count.Load()); got != 1 {
		t.Errorf("server received %d datagrams, want 1", got)
	}
}

// The default client retransmits: one lost datagram is not a failure.
func TestClient_DefaultRetransmits(t *testing.T) {
	if auth.DefaultUDPAttempts < 2 {
		t.Fatalf("DefaultUDPAttempts = %d, want at least 2", auth.DefaultUDPAttempts)
	}
	srv := startDroppingUDPServer(t, 1)
	c := auth.NewClient(auth.WithServers(srv.addr), auth.WithTimeout(retryAttemptTimeout))
	if _, err := c.Query(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
}
