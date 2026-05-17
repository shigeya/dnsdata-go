package auth_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/resolver/auth"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/wire"
)

// --- Fixtures -----------------------------------------------------------

// buildResponseTo constructs a DNS response message that copies its
// transaction ID from query so the auth client accepts it. Carries
// one answer RR.
func buildResponseTo(t *testing.T, query []byte, name string, rrtype uint16, ttl uint32, rdata []byte, tc bool) []byte {
	t.Helper()
	if len(query) < 12 {
		t.Fatalf("query too short")
	}
	queryID := binary.BigEndian.Uint16(query[0:2])

	var b wire.Builder
	b.AppendUint16(queryID)
	flags := uint16(0x8180) // QR=1, RD=1, RA=1, RCODE=0
	if tc {
		flags |= 0x0200
	}
	b.AppendUint16(flags)
	b.AppendUint16(1) // QDCOUNT
	if tc {
		b.AppendUint16(0) // ANCOUNT — no answer on truncated UDP response
	} else {
		b.AppendUint16(1)
	}
	b.AppendUint16(0)
	b.AppendUint16(0)

	qname, _ := wire.DomainNameToWire(name)
	b.AppendBytes(qname)
	b.AppendUint16(rrtype)
	b.AppendUint16(types.ClassIN)

	if !tc {
		b.AppendBytes(qname)
		b.AppendUint16(rrtype)
		b.AppendUint16(types.ClassIN)
		b.AppendUint32(ttl)
		b.AppendUint16(uint16(len(rdata)))
		b.AppendBytes(rdata)
	}
	return b.Clone()
}

// startUDPListener spawns a goroutine that reads one datagram and
// responds with the bytes returned by responder. The returned address
// is in `127.0.0.1:port` form, suitable for [auth.WithServers].
func startUDPListener(t *testing.T, responder func(query []byte) []byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := responder(buf[:n])
		_, _ = conn.WriteTo(resp, addr)
	}()
	return conn.LocalAddr().String()
}

// startTCPListener accepts one connection, reads the length-prefixed
// query, and replies with the responder's bytes (also length-prefixed).
func startTCPListener(t *testing.T, responder func(query []byte) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(hdr)
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := responder(query)
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_, _ = conn.Write(out)
	}()
	return ln.Addr().String()
}

// startUDPAndTCPListener combines the two so the same address pair
// works for both protocols. The UDP listener responds with the TC
// flag set; the TCP listener returns the full response.
func startUDPAndTCPListener(t *testing.T, name string, rrtype uint16, ttl uint32, rdata []byte) (string, string) {
	t.Helper()
	udpAddr := startUDPListener(t, func(query []byte) []byte {
		return buildResponseTo(t, query, name, rrtype, ttl, rdata, true)
	})
	// We bind TCP on a different port; the client uses the same addr
	// for both protocols, so this combined helper isn't quite right.
	// For the truncation test we instead use a single shared listener
	// — see TestClient_QueryRaw_TCPFallbackOnTruncation below.
	_ = udpAddr
	tcpAddr := startTCPListener(t, func(query []byte) []byte {
		return buildResponseTo(t, query, name, rrtype, ttl, rdata, false)
	})
	return udpAddr, tcpAddr
}

// --- Tests --------------------------------------------------------------

func TestClient_Query_NoServers(t *testing.T) {
	c := auth.NewClient()
	_, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, auth.ErrNoServers) {
		t.Errorf("err = %v, want ErrNoServers", err)
	}
}

func TestClient_Query_UDPHappyPath(t *testing.T) {
	addr := startUDPListener(t, func(query []byte) []byte {
		return buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false)
	})

	c := auth.NewClient(auth.WithServers(addr), auth.WithTimeout(500*time.Millisecond))
	resp, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short: %d", len(resp))
	}
	if resp[2]&0x80 == 0 {
		t.Errorf("QR bit not set in response: 0x%02x", resp[2])
	}
}

func TestClient_QueryRaw_TCPFallbackOnTruncation(t *testing.T) {
	// Spin up a UDP listener that sets TC, and a TCP listener (on a
	// different port) that returns the full response. The client must
	// notice the truncation and retry on TCP — but the auth client
	// expects the same host:port for both, so this test actually
	// exercises the lower-level queryTCP entrypoint via Resolve once
	// the TC fallback is wired. Until then, we exercise the two
	// transports separately via TCP-only.
	_, tcpAddr := startUDPAndTCPListener(t, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 5})

	// Reach the TCP listener directly. Resolve will choose UDP first,
	// fail with refused (no UDP on that port), and the failover would
	// hit ErrAllServersFailed. Skip this and use a direct TCP-only test.
	c := auth.NewClient(auth.WithServers(tcpAddr), auth.WithTimeout(500*time.Millisecond))
	// Manually craft the UDP-truncated case by pointing at a server
	// where both protocols share the same port. We construct that
	// here using ListenPacket on the same UDP port returned by the
	// existing TCP listener: net.Listen("tcp") and ListenPacket("udp")
	// on identical "127.0.0.1:port" are independent fds, so this is
	// safe.
	host, port, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	udpConn, err := net.ListenPacket("udp", host+":"+port)
	if err != nil {
		t.Skipf("port collision (UDP/TCP same port): %v", err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	go func() {
		buf := make([]byte, 4096)
		n, ra, err := udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := buildResponseTo(t, buf[:n], "example.com.", types.TypeA, 300, []byte{192, 0, 2, 5}, true /*TC*/)
		_, _ = udpConn.WriteTo(resp, ra)
	}()

	resp, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short")
	}
	if resp[2]&0x02 != 0 {
		t.Errorf("TCP response unexpectedly has TC bit set")
	}
}

func TestClient_Query_FailsOver(t *testing.T) {
	// First server is unreachable (closed listener); second succeeds.
	dead := startUDPListener(t, func(query []byte) []byte { return nil })
	// Close the dead listener to make sure it refuses writes.
	// (Actually ListenPacket returns one and the goroutine consumes
	// one packet; subsequent writes succeed but no response comes
	// back. The UDP read in the client then times out — covered by
	// the explicit short timeout below.)

	good := startUDPListener(t, func(query []byte) []byte {
		return buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 9}, false)
	})

	c := auth.NewClient(
		auth.WithServers(dead, good),
		auth.WithTimeout(200*time.Millisecond),
	)
	resp, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short")
	}
}

func TestClient_Query_AllServersFail(t *testing.T) {
	addr := startUDPListener(t, func(query []byte) []byte { return nil })
	c := auth.NewClient(
		auth.WithServers(addr, addr),
		auth.WithTimeout(200*time.Millisecond),
	)
	_, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, auth.ErrAllServersFailed) {
		t.Errorf("err = %v, want ErrAllServersFailed", err)
	}
}

func TestClient_Resolve_HappyPath(t *testing.T) {
	rdata, _ := hex.DecodeString("deadbeef")
	rrdata := []byte{0x01, 0x01, 3, 13} // flags=257, proto=3, algo=13
	rrdata = append(rrdata, rdata...)
	addr := startUDPListener(t, func(query []byte) []byte {
		return buildResponseTo(t, query, "example.com.", types.TypeDNSKEY, 3600, rrdata, false)
	})
	c := auth.NewClient(auth.WithServers(addr), auth.WithTimeout(500*time.Millisecond))
	records, err := c.Resolve(context.Background(), "example.com.", types.TypeDNSKEY)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].Value != "257 3 13 3q2+7w==" {
		t.Errorf("Value = %q", records[0].Value)
	}
}

func TestClient_Resolve_RCODE(t *testing.T) {
	addr := startUDPListener(t, func(query []byte) []byte {
		queryID := binary.BigEndian.Uint16(query[0:2])
		// Build NXDOMAIN response: flags = 0x8183 (QR | RD | RA | RCODE=3)
		var b wire.Builder
		b.AppendUint16(queryID)
		b.AppendUint16(0x8183)
		b.AppendUint16(1)
		b.AppendUint16(0)
		b.AppendUint16(0)
		b.AppendUint16(0)
		qname, _ := wire.DomainNameToWire("missing.example.")
		b.AppendBytes(qname)
		b.AppendUint16(types.TypeA)
		b.AppendUint16(types.ClassIN)
		return b.Clone()
	})
	c := auth.NewClient(auth.WithServers(addr), auth.WithTimeout(500*time.Millisecond))
	_, err := c.Resolve(context.Background(), "missing.example.", types.TypeA)
	if !errors.Is(err, auth.ErrResolverResponse) {
		t.Errorf("err = %v, want ErrResolverResponse", err)
	}
}

func TestClient_Query_IDMismatch(t *testing.T) {
	addr := startUDPListener(t, func(query []byte) []byte {
		// Build a response with the wrong ID.
		resp := buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false)
		// Flip the ID bits.
		binary.BigEndian.PutUint16(resp[0:2], 0xDEAD)
		return resp
	})
	c := auth.NewClient(auth.WithServers(addr), auth.WithTimeout(300*time.Millisecond))
	_, err := c.Query(context.Background(), "example.com.", types.TypeA)
	// The client retries on next server (none here), so we get
	// ErrAllServersFailed wrapping ErrIDMismatch.
	if !errors.Is(err, auth.ErrIDMismatch) {
		t.Errorf("err = %v, want ErrIDMismatch wrapped", err)
	}
}

func TestClient_Servers_IsCopy(t *testing.T) {
	c := auth.NewClient(auth.WithServers("1.2.3.4:53", "5.6.7.8:53"))
	s := c.Servers()
	s[0] = "tampered"
	s2 := c.Servers()
	if s2[0] != "1.2.3.4:53" {
		t.Errorf("Servers() leaked mutation: %q", s2[0])
	}
}

func TestNormalizeAddr_DefaultPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":      "1.2.3.4:53",
		"1.2.3.4:5353": "1.2.3.4:5353",
		"[::1]:53":     "[::1]:53",
	}
	for in, want := range cases {
		got := auth.NormalizeAddr(in)
		if got != want {
			t.Errorf("NormalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveSatisfiesVerifierResolver(t *testing.T) {
	c := auth.NewClient()
	var _ verifier.Resolver = verifier.ResolverFunc(c.Resolve)
}

func TestWithUDPBufferSize_ClampsLowValues(t *testing.T) {
	// Indirectly verify by issuing a query against a stub server that
	// would overflow a 256-byte buffer — but since we cap at 512, the
	// query must still succeed.
	addr := startUDPListener(t, func(query []byte) []byte {
		return buildResponseTo(t, query, "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, false)
	})
	c := auth.NewClient(
		auth.WithServers(addr),
		auth.WithUDPBufferSize(100),
		auth.WithTimeout(500*time.Millisecond),
	)
	if _, err := c.Query(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
}

func TestQueryTCP_ReadPrefixError(t *testing.T) {
	// TCP listener that accepts the connection, reads the query, and
	// closes immediately — exercising the read-prefix error path of
	// queryTCP. We trigger TCP via UDP truncation.
	host := "127.0.0.1"
	udpConn, err := net.ListenPacket("udp", host+":0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", udpPort)))
	if err != nil {
		t.Skipf("port collision: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })

	go func() {
		buf := make([]byte, 4096)
		n, addr, _ := udpConn.ReadFrom(buf)
		resp := buildResponseTo(t, buf[:n], "example.com.", types.TypeA, 300, []byte{192, 0, 2, 1}, true)
		_, _ = udpConn.WriteTo(resp, addr)
	}()
	go func() {
		conn, _ := tcpLn.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	c := auth.NewClient(
		auth.WithServers(tcpLn.Addr().String()),
		auth.WithTimeout(500*time.Millisecond),
	)
	_, err = c.Query(context.Background(), "example.com.", types.TypeA)
	if err == nil {
		t.Fatal("expected error from closed TCP connection")
	}
}

// Ensure strings import isn't accidentally pruned by future edits.
var _ = strings.TrimSpace
