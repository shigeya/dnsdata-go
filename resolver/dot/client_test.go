package dot_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/resolver/dot"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/wire"
)

const testServerName = "dot.test"

// testCert is a self-signed certificate for 127.0.0.1 and dot.test,
// and a pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testServerName},
		DNSNames:     []string{testServerName},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// startDoTListener serves DNS over TLS on 127.0.0.1: each connection
// gets one length-prefixed query and the responder's reply.
func startDoTListener(t *testing.T, cert tls.Certificate, responder func(query []byte) []byte) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOne(conn, responder)
		}
	}()
	return ln.Addr().String()
}

func serveOne(conn net.Conn, responder func(query []byte) []byte) {
	defer conn.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(hdr))
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}
	resp := responder(query)
	out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
	_, _ = conn.Write(append(out, resp...))
}

// answerA replies to query with one A record for its question.
func answerA(t *testing.T, query []byte, rcode uint16) []byte {
	t.Helper()
	q, err := wire.ParseMessage(query)
	if err != nil {
		t.Errorf("server: bad query: %v", err)
		return nil
	}
	var b wire.Builder
	b.AppendUint16(binary.BigEndian.Uint16(query))
	b.AppendUint16(0x8180 | rcode) // QR RD RA
	b.AppendUint16(1)
	b.AppendUint16(1)
	b.AppendUint16(0)
	b.AppendUint16(0)
	name, _ := wire.DomainNameToWire(q.Question.Name)
	for i := 0; i < 2; i++ {
		b.AppendBytes(name)
		b.AppendUint16(types.TypeA)
		b.AppendUint16(types.ClassIN)
	}
	b.AppendUint32(300)
	b.AppendUint16(4)
	b.AppendBytes([]byte{192, 0, 2, 1})
	return b.Clone()
}

func newClient(pool *x509.CertPool, addrs ...string) *dot.Client {
	return dot.NewClient(
		dot.WithServers(addrs...),
		dot.WithTLSConfig(&tls.Config{RootCAs: pool}),
		dot.WithTimeout(2*time.Second),
	)
}

func TestClient_Resolve(t *testing.T) {
	cert, pool := testCert(t)
	addr := startDoTListener(t, cert, func(q []byte) []byte { return answerA(t, q, 0) })
	resp, err := newClient(pool, addr).Resolve(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp.RCode != 0 || len(resp.Records) != 1 || resp.Records[0].Value != "192.0.2.1" {
		t.Errorf("Resolve = %+v", resp)
	}
}

func TestClient_RCodeIsData(t *testing.T) {
	cert, pool := testCert(t)
	addr := startDoTListener(t, cert, func(q []byte) []byte { return answerA(t, q, uint16(types.RCodeNXDomain)) })
	resp, err := newClient(pool, addr).Resolve(context.Background(), "nope.example.com.", types.TypeA)
	if err != nil || resp.RCode != uint8(types.RCodeNXDomain) {
		t.Errorf("Resolve = %+v, %v; want RCODE 3 and no error", resp, err)
	}
}

// RFC 8310 strict privacy: the server certificate must chain to a
// trusted root and match the name (or address) the client expects.
func TestClient_AuthenticatesServer(t *testing.T) {
	cert, pool := testCert(t)
	addr := startDoTListener(t, cert, func(q []byte) []byte { return answerA(t, q, 0) })
	cases := map[string]*dot.Client{
		"untrusted root": dot.NewClient(dot.WithServers(addr), dot.WithTimeout(2*time.Second)),
		"name mismatch": dot.NewClient(dot.WithServers(addr), dot.WithTimeout(2*time.Second),
			dot.WithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "other.test"})),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Query(context.Background(), "www.example.com.", types.TypeA)
			if !errors.Is(err, dot.ErrDoT) || !errors.Is(err, dot.ErrAllServersFailed) {
				t.Errorf("err = %v, want ErrDoT and ErrAllServersFailed", err)
			}
		})
	}
	ok := dot.NewClient(dot.WithServers(addr), dot.WithTimeout(2*time.Second),
		dot.WithTLSConfig(&tls.Config{RootCAs: pool, ServerName: testServerName}))
	if _, err := ok.Query(context.Background(), "www.example.com.", types.TypeA); err != nil {
		t.Errorf("ServerName %s: %v", testServerName, err)
	}
}

func TestClient_WithCheckingDisabled(t *testing.T) {
	cert, pool := testCert(t)
	for _, cd := range []bool{false, true} {
		got := make(chan bool, 1)
		addr := startDoTListener(t, cert, func(q []byte) []byte {
			got <- q[3]&byte(wire.FlagCD) != 0
			return answerA(t, q, 0)
		})
		c := dot.NewClient(dot.WithServers(addr), dot.WithTLSConfig(&tls.Config{RootCAs: pool}),
			dot.WithCheckingDisabled(cd))
		if _, err := c.Query(context.Background(), "www.example.com.", types.TypeA); err != nil {
			t.Fatal(err)
		}
		if bit := <-got; bit != cd {
			t.Errorf("CheckingDisabled(%v): CD on the wire = %v", cd, bit)
		}
	}
}

func TestClient_FailsOver(t *testing.T) {
	cert, pool := testCert(t)
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()
	addr := startDoTListener(t, cert, func(q []byte) []byte { return answerA(t, q, 0) })
	if _, err := newClient(pool, deadAddr, addr).Query(context.Background(), "www.example.com.", types.TypeA); err != nil {
		t.Errorf("Query with a dead first server: %v", err)
	}
}

func TestClient_IDMismatch(t *testing.T) {
	cert, pool := testCert(t)
	addr := startDoTListener(t, cert, func(q []byte) []byte {
		resp := answerA(t, q, 0)
		resp[0] ^= 0xff
		return resp
	})
	_, err := newClient(pool, addr).Query(context.Background(), "www.example.com.", types.TypeA)
	if !errors.Is(err, dot.ErrIDMismatch) {
		t.Errorf("err = %v, want ErrIDMismatch", err)
	}
}

func TestClient_ShortResponse(t *testing.T) {
	cert, pool := testCert(t)
	addr := startDoTListener(t, cert, func([]byte) []byte { return []byte{0, 1, 2} })
	_, err := newClient(pool, addr).Query(context.Background(), "www.example.com.", types.TypeA)
	if !errors.Is(err, dot.ErrResponseTooShort) {
		t.Errorf("err = %v, want ErrResponseTooShort", err)
	}
}

func TestClient_NoServers(t *testing.T) {
	if _, err := dot.NewClient().Query(context.Background(), "example.com.", types.TypeA); !errors.Is(err, dot.ErrNoServers) {
		t.Errorf("err = %v, want ErrNoServers", err)
	}
}

func TestClient_CanceledContext(t *testing.T) {
	cert, pool := testCert(t)
	addr := startDoTListener(t, cert, func(q []byte) []byte { return answerA(t, q, 0) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newClient(pool, addr).Query(ctx, "www.example.com.", types.TypeA); err == nil {
		t.Error("Query with a canceled context: want error")
	}
}

func TestNormalizeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":       "192.0.2.1:853",
		"192.0.2.1:8853":  "192.0.2.1:8853",
		"dns.example":     "dns.example:853",
		"[2001:db8::1]:5": "[2001:db8::1]:5",
		"2001:db8::1":     "[2001:db8::1]:853",
	} {
		if got := dot.NormalizeAddr(in); got != want {
			t.Errorf("NormalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClient_ServersIsCopy(t *testing.T) {
	c := dot.NewClient(dot.WithServers("192.0.2.1"))
	s := c.Servers()
	s[0] = "changed"
	if c.Servers()[0] != "192.0.2.1:853" {
		t.Errorf("Servers() = %v", c.Servers())
	}
}

func TestResolveSatisfiesVerifierResolver(t *testing.T) {
	c := dot.NewClient()
	var _ verifier.Resolver = verifier.ResolverFunc(c.Resolve)
}
