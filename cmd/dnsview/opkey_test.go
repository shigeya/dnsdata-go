package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// The OPKEY view is checked against a hierarchy signed here, since the
// shared vectors in testdata/signed/ carry no TLSA RRset. The owner
// names are given in full: dnsview composes no names.

const (
	opkeyOwner = "_issuer-key._op.example.test."
	badOwner   = "_bad._op.example.test."
)

var opkeyFrom = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// opkeyLine is a line with the "opkey" member decoded.
type opkeyLine struct {
	Query  query           `json:"query"`
	Error  string          `json:"error"`
	Result json.RawMessage `json:"result"`
	OPKEY  *opkeyView      `json:"opkey"`
}

type opkeyFixture struct {
	auth        verifier.Resolver
	anchorsPath string
	usable      string // presentation form of the usable record
}

// newOPKEYFixture signs "." → "test." → "example.test." with a TLSA
// RRset at opkeyOwner holding one usable and one unusable OPKEY record,
// and a TLSA RRset at badOwner whose RDATA is too short to be TLSA.
func newOPKEYFixture(t *testing.T) opkeyFixture {
	t.Helper()
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	usable, err := zone.NewOPKEYForSPKI(zone.OPKEYMatchingSHA256, spki)
	if err != nil {
		t.Fatal(err)
	}

	rootKey := newKSK(t, ".")
	tldKey := newKSK(t, "test.")
	leafKey := newKSK(t, "example.test.")
	root := signText(t, ".", ". 86400 NS a.root.test.\ntest. 86400 NS ns.test.\ntest. 86400 DS "+dsOf(t, tldKey)+"\n", rootKey)
	tld := signText(t, "test.", "test. 3600 NS ns.test.\nexample.test. 3600 NS ns.example.test.\nexample.test. 3600 DS "+dsOf(t, leafKey)+"\n", tldKey)
	leaf := signText(t, "example.test.", strings.Join([]string{
		"example.test. 3600 NS ns.example.test.",
		"www.example.test. 3600 A 192.0.2.10",
		opkeyOwner + " 3600 TLSA " + usable.String(),
		opkeyOwner + " 3600 TLSA 0 0 0 aabb",
		badOwner + ` 3600 TLSA \# 2 0301`,
	}, "\n")+"\n", leafKey)

	auth, err := memory.New(memory.WithZone(".", root), memory.WithZone("test.", tld), memory.WithZone("example.test.", leaf))
	if err != nil {
		t.Fatal(err)
	}
	return opkeyFixture{auth: withOctets(auth), anchorsPath: writeRootAnchors(t, rootKey), usable: usable.String()}
}

// withOctets gives r's records their RDATA octets, as the network
// clients' records have (dnsview's Verifier has no zone handlers, so a
// TLSA record without octets would not encode). The records are
// encoded once through the handlers registered by the fixture.
func withOctets(r verifier.Resolver) verifier.Resolver {
	return verifier.ResolverFunc(func(ctx context.Context, name string, qtype uint16) (resolver.Response, error) {
		resp, err := r.Query(ctx, name, qtype)
		if err != nil {
			return resp, err
		}
		records := make([]*zone.ResourceRecord, 0, len(resp.Records))
		for _, rr := range resp.Records {
			var b wire.Builder
			if err := rr.WireBody(&b); err != nil {
				return resolver.Response{}, err
			}
			received, err := zone.NewResourceRecordWithRData(rr.Label, rr.TTL, rr.Class, rr.Type, rr.Value, b.Bytes()[2:])
			if err != nil {
				return resolver.Response{}, err
			}
			records = append(records, received)
		}
		return resolver.Response{Records: records, AD: resp.AD, RCode: resp.RCode}, nil
	})
}

func newKSK(t *testing.T, owner string) *signer.Key {
	t.Helper()
	k, err := signer.GenerateKey(owner, types.AlgoECDSAP256SHA256, signer.FlagsKSK)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func dsOf(t *testing.T, k *signer.Key) string {
	t.Helper()
	ds, err := k.DS(signer.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func signText(t *testing.T, apex, text string, key *signer.Key) *zone.Zone {
	t.Helper()
	var z zone.Zone
	if err := z.ReadStringStrict(text); err != nil {
		t.Fatalf("%s: %v", apex, err)
	}
	opts := signer.Options{Inception: opkeyFrom, Expiration: opkeyFrom.AddDate(1, 0, 0)}
	signed, err := signer.SignZone(&z, apex, []*signer.Key{key}, opts)
	if err != nil {
		t.Fatalf("sign %s: %v", apex, err)
	}
	return signed
}

func writeRootAnchors(t *testing.T, rootKey *signer.Key) string {
	t.Helper()
	anchors, err := signer.RootAnchors(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "anchors.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := dnssec.WriteAnchors(f, anchors); err != nil {
		t.Fatal(err)
	}
	return path
}

func (fx opkeyFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	base := []string{"-server", "192.0.2.53", "-anchors", fx.anchorsPath}
	return runWith(t, fx.auth, opkeyFrom.AddDate(0, 6, 0), append(base, args...)...)
}

func decodeOPKEYLine(t *testing.T, out string) opkeyLine {
	t.Helper()
	var l opkeyLine
	if err := json.Unmarshal([]byte(out), &l); err != nil {
		t.Fatalf("line %q: %v", out, err)
	}
	return l
}

func TestRun_OPKEYReadsTLSAAnswer(t *testing.T) {
	fx := newOPKEYFixture(t)
	code, out, stderr := fx.run(t, "-opkey", opkeyOwner)
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s, stdout %s", code, stderr, out)
	}
	l := decodeOPKEYLine(t, out)
	if l.Query.Type != "TLSA" {
		t.Errorf("query.type %q, want TLSA (the -opkey default)", l.Query.Type)
	}
	if v := decodeResult(t, l.Result).Verdict; v != verifier.VerdictSecure {
		t.Fatalf("verdict %s, want secure", v)
	}
	if l.OPKEY == nil || l.OPKEY.Error != "" || len(l.OPKEY.Records) != 2 {
		t.Fatalf("opkey %+v, want two records and no error", l.OPKEY)
	}
	got := map[string]opkeyRecord{}
	for _, r := range l.OPKEY.Records {
		got[r.Value] = r
	}
	if r := got[fx.usable]; !r.Usable || r.Reason != "" {
		t.Errorf("usable record %+v, want usable without reason", r)
	}
	if r := got["0 0 0 aabb"]; r.Usable || r.Reason != "OPKEY usage 0 (want 3)" {
		t.Errorf("unusable record %+v, want the usage reason", r)
	}
}

func TestRun_OPKEYMalformedRecordFailsTheRRset(t *testing.T) {
	fx := newOPKEYFixture(t)
	code, out, _ := fx.run(t, "-opkey", badOwner)
	if code != exitQueryError {
		t.Errorf("exit %d, want %d", code, exitQueryError)
	}
	l := decodeOPKEYLine(t, out)
	if l.OPKEY == nil || !strings.Contains(l.OPKEY.Error, "length 2") || len(l.OPKEY.Records) != 0 {
		t.Errorf("opkey %+v, want an RRset error and no records", l.OPKEY)
	}
}

// Without -opkey, and for answers of other types under it, the line is
// exactly as before: no "opkey" member.
func TestRun_OPKEYAbsentUnlessAsked(t *testing.T) {
	fx := newOPKEYFixture(t)
	for name, args := range map[string][]string{
		"TLSA without -opkey": {"-type", "TLSA", opkeyOwner},
		"A with -opkey":       {"-opkey", "-type", "A", "www.example.test."},
	} {
		code, out, stderr := fx.run(t, args...)
		if code != exitOK {
			t.Fatalf("%s: exit %d, stderr %s", name, code, stderr)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &top); err != nil {
			t.Fatal(err)
		}
		if _, ok := top["opkey"]; ok || len(top) != 3 {
			t.Errorf("%s: top-level keys %v, want query, server, result", name, keys(top))
		}
	}
}

func TestRun_OPKEYTypeUnallocatedIsAUsageError(t *testing.T) {
	code, out, stderr := runWith(t, nil, opkeyFrom, "-server", "192.0.2.53", "-type", "OPKEY", "x.test.")
	if code != exitUsage || out != "" || !strings.Contains(stderr, "not allocated") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}

func TestReadOPKEY_NoView(t *testing.T) {
	if v := readOPKEY(nil); v != nil {
		t.Errorf("readOPKEY(nil) = %+v", v)
	}
	if v := readOPKEY(&verifier.Result{}); v != nil {
		t.Errorf("readOPKEY(no answer) = %+v", v)
	}
	res := &verifier.Result{Answer: &verifier.Answer{Type: types.TypeA,
		Records: []verifier.AnswerRecord{{RData: []byte{192, 0, 2, 1}}}}}
	if v := readOPKEY(res); v != nil {
		t.Errorf("readOPKEY(A answer) = %+v", v)
	}
}
