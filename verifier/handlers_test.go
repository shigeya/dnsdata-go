package verifier_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/resolver/auth"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// updateHandlers regenerates testdata/handlers. Signatures are ECDSA and
// differ on every run, so regenerate only when the zone changes.
var updateHandlers = flag.Bool("update", false, "regenerate testdata/handlers")

// handlersDir holds a signed root zone whose TLSA, SMIMEA, SVCB and
// HTTPS records are written in RFC 3597 generic form, so that a server
// in this test binary sends their octets without the zone handlers. The
// resolver client presents them by type, which only the zone handlers
// encode; this binary never registers them (the signer would, which is
// why the zone is read from a file rather than signed here).
var handlersDir = filepath.Join("testdata", "handlers")

const handlersZoneText = `. 86400 SOA a.root.test. hostmaster.root.test. 1 1800 900 604800 86400
. 86400 NS a.root.test.
a.root.test. 86400 A 192.0.2.1
svc.example.test. 3600 SVCB 1 target.example.
www.example.test. 3600 HTTPS 1 . alpn=h2
_443._tcp.www.example.test. 3600 TLSA 3 1 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
x._smimecert.example.test. 3600 SMIMEA 3 0 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
`

// zoneHandlerTypes are the types whose presentation form only
// zone.RegisterHandlers encodes.
var zoneHandlerTypes = map[uint16]bool{
	types.TypeTLSA: true, types.TypeSMIMEA: true, types.TypeSVCB: true, types.TypeHTTPS: true,
}

// handlersClock is inside the validity window of testdata/handlers.
var handlersClock = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// zoneHandlerAnswers are the zone-handler-type records of
// handlersZoneText, in presentation form.
var zoneHandlerAnswers = []struct {
	qname, value string
	qtype        uint16
}{
	{"svc.example.test.", "1 target.example.", types.TypeSVCB},
	{"www.example.test.", "1 . alpn=h2", types.TypeHTTPS},
	{"_443._tcp.www.example.test.", "3 1 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", types.TypeTLSA},
	{"x._smimecert.example.test.", "3 0 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", types.TypeSMIMEA},
}

// TestNewVerifier_ValidatesZoneHandlerTypesOverTheWire validates TLSA,
// SMIMEA, SVCB and HTTPS answers received by the auth client, with the
// Verifier's default registry (DNSSEC handlers only): the octets the
// client received are signed as they are.
func TestNewVerifier_ValidatesZoneHandlerTypesOverTheWire(t *testing.T) {
	if *updateHandlers {
		writeHandlersZone(t)
	}
	auth, anchors := handlersWireResolver(t)
	clock := handlersClock
	for _, c := range zoneHandlerAnswers {
		t.Run(types.RRTypeName(c.qtype), func(t *testing.T) {
			v, err := verifier.NewVerifier(
				verifier.WithResolver(verifier.ResolverFunc(auth.Resolve)),
				verifier.WithTrustAnchors(anchors),
				verifier.WithClock(func() time.Time { return clock }),
			)
			if err != nil {
				t.Fatal(err)
			}
			res, err := v.Validate(context.Background(), c.qname, c.qtype)
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != verifier.VerdictSecure {
				t.Fatalf("verdict %s, want secure (%+v)", res.Verdict, res)
			}
			if res.Answer == nil || len(res.Answer.Records) != 1 || res.Answer.Records[0].Value != c.value {
				t.Fatalf("answer %+v, want one %s record %q", res.Answer, types.RRTypeName(c.qtype), c.value)
			}
		})
	}
}

// TestNewVerifier_LeavesZoneHandlersUnregistered checks that
// constructing a Verifier does not register the zone handlers.
func TestNewVerifier_LeavesZoneHandlersUnregistered(t *testing.T) {
	if *updateHandlers {
		t.Skip("the signer registered every handler")
	}
	if _, err := verifier.NewVerifier(verifier.WithResolver(verifier.ResolverFunc(nil))); err != nil {
		t.Fatal(err)
	}
	for rrtype := range zoneHandlerTypes {
		rr := &zone.ResourceRecord{Label: "x.test.", Class: types.ClassIN, Type: rrtype, Value: "1 ."}
		if h := rr.Handler(); h != nil {
			t.Errorf("%s handler %T is registered", types.RRTypeName(rrtype), h)
		}
	}
}

// TestNewVerifier_NoEncoderNamesTheRegistration checks that an answer
// held in presentation form without its octets (a cache that dropped
// them) fails with an error that names the registration it needs.
func TestNewVerifier_NoEncoderNamesTheRegistration(t *testing.T) {
	if *updateHandlers {
		t.Skip("the signer registered every handler")
	}
	authority, anchors := presentedAuthority(t)
	v, err := verifier.NewVerifier(
		verifier.WithResolver(authority),
		verifier.WithTrustAnchors(anchors),
		verifier.WithClock(func() time.Time { return handlersClock }),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Validate(context.Background(), "svc.example.test.", types.TypeSVCB)
	if err == nil || !strings.Contains(err.Error(), "verifier.WithZoneHandlers") {
		t.Fatalf("error %v, want one naming verifier.WithZoneHandlers", err)
	}
}

// TestNewVerifier_ValidatesPresentedZoneHandlerTypes validates TLSA,
// SMIMEA, SVCB and HTTPS answers that an in-memory authority returns in
// presentation form without their octets, with the zone handlers in the
// Verifier's own registry: through WithZoneHandlers, and through
// WithRegistry with both handler sets. The default registry is left
// without them.
func TestNewVerifier_ValidatesPresentedZoneHandlerTypes(t *testing.T) {
	if *updateHandlers {
		t.Skip("the signer registered every handler")
	}
	authority, anchors := presentedAuthority(t)
	both := zone.NewRegistry()
	dnssec.RegisterHandlersInto(both)
	zone.RegisterHandlersInto(both)
	options := map[string]verifier.Option{
		"WithZoneHandlers": verifier.WithZoneHandlers(),
		"WithRegistry":     verifier.WithRegistry(both),
	}
	for name, opt := range options {
		for _, c := range zoneHandlerAnswers {
			t.Run(name+"/"+types.RRTypeName(c.qtype), func(t *testing.T) {
				v, err := verifier.NewVerifier(
					verifier.WithResolver(authority),
					verifier.WithTrustAnchors(anchors),
					verifier.WithClock(func() time.Time { return handlersClock }),
					opt,
				)
				if err != nil {
					t.Fatal(err)
				}
				res, err := v.Validate(context.Background(), c.qname, c.qtype)
				if err != nil {
					t.Fatal(err)
				}
				if res.Verdict != verifier.VerdictSecure {
					t.Fatalf("verdict %s, want secure (%+v)", res.Verdict, res)
				}
				if res.Answer == nil || len(res.Answer.Records) != 1 || res.Answer.Records[0].Value != c.value {
					t.Fatalf("answer %+v, want one %s record %q", res.Answer, types.RRTypeName(c.qtype), c.value)
				}
			})
		}
	}
	for rrtype := range zoneHandlerTypes {
		if zone.DefaultRegistry().Lookup(rrtype) != nil {
			t.Errorf("%s handler is registered in the default registry", types.RRTypeName(rrtype))
		}
	}
}

// TestNewVerifier_ZoneHandlersExcludeRegistry checks that
// WithZoneHandlers and WithRegistry together are a configuration error.
func TestNewVerifier_ZoneHandlersExcludeRegistry(t *testing.T) {
	_, err := verifier.NewVerifier(
		verifier.WithResolver(verifier.ResolverFunc(nil)),
		verifier.WithZoneHandlers(),
		verifier.WithRegistry(zone.NewRegistry()),
	)
	if !errors.Is(err, verifier.ErrConfig) {
		t.Fatalf("error %v, want ErrConfig", err)
	}
}

// presentedAuthority serves the signed zone of testdata/handlers with
// its zone-handler-type records in presentation form, as an in-memory
// authority returns records it holds as text (no RDATA octets).
func presentedAuthority(t *testing.T) (*memory.Authority, *dnssec.RootAnchors) {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(handlersDir, "root.zone"))
	if err != nil {
		t.Fatal(err)
	}
	var z zone.Zone
	for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n") {
		for _, c := range zoneHandlerAnswers {
			prefix := c.qname + " 3600 IN " + types.RRTypeName(c.qtype) + " "
			if strings.HasPrefix(line, prefix) {
				line = prefix + c.value
			}
		}
		if err := z.ReadString(line); err != nil {
			t.Fatal(err)
		}
	}
	authority, err := memory.New(memory.WithZone(".", &z))
	if err != nil {
		t.Fatal(err)
	}
	_, anchors := handlersWireResolver(t)
	return authority, anchors
}

// handlersWireResolver serves the signed zone from an in-memory
// authority over UDP and returns an auth client pointed at it.
func handlersWireResolver(t *testing.T) (*auth.Client, *dnssec.RootAnchors) {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(handlersDir, "root.zone"))
	if err != nil {
		t.Fatal(err)
	}
	var z zone.Zone
	if err := z.ReadString(string(text)); err != nil {
		t.Fatal(err)
	}
	authority, err := memory.New(memory.WithZone(".", &z))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(handlersDir, "root-anchors.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	anchors, err := dnssec.ReadAnchors(f)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveUDP(t, authority)
	return auth.NewClient(auth.WithServers(addr), auth.WithTimeout(2*time.Second)), anchors
}

// serveUDP answers every datagram from authority until the test ends.
func serveUDP(t *testing.T, authority *memory.Authority) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, err := answerQuery(authority, buf[:n])
			if err != nil {
				t.Errorf("answer: %v", err)
				return
			}
			_, _ = conn.WriteTo(resp, addr)
		}
	}()
	return conn.LocalAddr().String()
}

// serverRegistry encodes the DNSSEC records the test server sends; it
// holds no zone handler.
var serverRegistry = func() *zone.Registry {
	reg := zone.NewRegistry()
	dnssec.RegisterHandlersInto(reg)
	return reg
}()

// answerQuery builds the wire response of authority to query. Records
// are encoded with WireBodyWith, so the generic-form records go out as
// their octets; the DNSSEC records use serverRegistry.
func answerQuery(authority *memory.Authority, query []byte) ([]byte, error) {
	msg, err := wire.ParseMessage(query)
	if err != nil {
		return nil, err
	}
	q := msg.Question
	resp, err := authority.Query(context.Background(), q.Name, q.Type)
	if err != nil {
		return nil, err
	}
	var b wire.Builder
	b.AppendUint16(binary.BigEndian.Uint16(query[0:2]))
	b.AppendUint16(0x8400 | uint16(resp.RCode)) // QR, AA
	b.AppendUint16(1)
	b.AppendUint16(uint16(len(resp.Records))) // every record in the answer section
	b.AppendUint16(0)
	b.AppendUint16(0)
	qname, err := wire.DomainNameToWire(q.Name)
	if err != nil {
		return nil, err
	}
	b.AppendBytes(qname)
	b.AppendUint16(q.Type)
	b.AppendUint16(q.Class)
	for _, rr := range resp.Records {
		if err := rr.WireHeader(&b); err != nil {
			return nil, err
		}
		b.AppendUint32(rr.TTL)
		if err := rr.WireBodyWith(serverRegistry, &b); err != nil {
			return nil, err
		}
	}
	return b.Clone(), nil
}

// writeHandlersZone signs handlersZoneText with a deterministic P-256
// key and writes it with the zone-handler types in generic form (only
// with -update).
func writeHandlersZone(t *testing.T) {
	t.Helper()
	seed := sha256.Sum256([]byte("handlers-root-ksk"))
	key, err := signer.ParseBINDPrivate(".", signer.FlagsKSK, []byte(
		"Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: "+
			base64.StdEncoding.EncodeToString(seed[:])+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	var z zone.Zone
	if err := z.ReadString(handlersZoneText); err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignZone(&z, ".", []*signer.Key{key}, signer.Options{
		Inception:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Expiration: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := signed.RecordsCanonical()
	if err != nil {
		t.Fatal(err)
	}
	lines := make([]string, 0, len(recs))
	for _, rr := range recs {
		lines = append(lines, genericIfZoneType(t, rr).String())
	}
	anchors, err := signer.RootAnchors(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := dnssec.WriteAnchors(&buf, anchors); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(handlersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"root.zone":         []byte(strings.Join(lines, "\n") + "\n"),
		"root-anchors.json": buf.Bytes(),
	} {
		if err := os.WriteFile(filepath.Join(handlersDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func genericIfZoneType(t *testing.T, rr *zone.ResourceRecord) *zone.ResourceRecord {
	t.Helper()
	if !zoneHandlerTypes[rr.Type] {
		return rr
	}
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatal(err)
	}
	g, err := zone.NewResourceRecordFromRData(rr.Label, rr.TTL, rr.Class, rr.Type, b.Clone()[2:])
	if err != nil {
		t.Fatal(err)
	}
	return g
}
