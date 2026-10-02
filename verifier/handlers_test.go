package verifier_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// updateHandlers regenerates testdata/handlers. Signatures are ECDSA and
// differ on every run, so regenerate only when the zone changes.
var updateHandlers = flag.Bool("update", false, "regenerate testdata/handlers")

// handlersDir holds a signed root zone whose answers need the bundled
// zone handlers (TLSA, SMIMEA, SVCB, HTTPS) to encode. It is read from a
// file, not signed in-process, because the signer registers every
// handler and would hide a verifier that does not.
var handlersDir = filepath.Join("testdata", "handlers")

const handlersZoneText = `. 86400 SOA a.root.test. hostmaster.root.test. 1 1800 900 604800 86400
. 86400 NS a.root.test.
a.root.test. 86400 A 192.0.2.1
svc.example.test. 3600 SVCB 1 target.example.
www.example.test. 3600 HTTPS 1 . alpn=h2
_443._tcp.www.example.test. 3600 TLSA 3 1 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
x._smimecert.example.test. 3600 SMIMEA 3 0 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
`

// TestNewVerifier_EncodesZoneHandlerTypes validates answers of types
// whose presentation form only the zone handlers encode, in a test
// binary that never calls zone.RegisterHandlers: NewVerifier must
// register what the signatures need by itself.
func TestNewVerifier_EncodesZoneHandlerTypes(t *testing.T) {
	if *updateHandlers {
		writeHandlersZone(t)
	}
	auth, anchors := loadHandlersZone(t)
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		qname string
		qtype uint16
	}{
		{"svc.example.test.", types.TypeSVCB},
		{"www.example.test.", types.TypeHTTPS},
		{"_443._tcp.www.example.test.", types.TypeTLSA},
		{"x._smimecert.example.test.", types.TypeSMIMEA},
	}
	for _, c := range cases {
		t.Run(types.RRTypeName(c.qtype), func(t *testing.T) {
			v, err := verifier.NewVerifier(
				verifier.WithResolver(auth),
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
			if res.Answer == nil || res.Answer.Type != c.qtype || len(res.Answer.Records) != 1 {
				t.Fatalf("answer %+v, want one %s record", res.Answer, types.RRTypeName(c.qtype))
			}
		})
	}
}

func loadHandlersZone(t *testing.T) (*memory.Authority, *dnssec.RootAnchors) {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(handlersDir, "root.zone"))
	if err != nil {
		t.Fatal(err)
	}
	var z zone.Zone
	if err := z.ReadString(string(text)); err != nil {
		t.Fatal(err)
	}
	auth, err := memory.New(memory.WithZone(".", &z))
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
	return auth, anchors
}

// writeHandlersZone signs handlersZoneText with a deterministic P-256
// key (only with -update).
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
	text, err := signed.PrintCanonical(0)
	if err != nil {
		t.Fatal(err)
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
		"root.zone":         []byte(text + "\n"),
		"root-anchors.json": buf.Bytes(),
	} {
		if err := os.WriteFile(filepath.Join(handlersDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
