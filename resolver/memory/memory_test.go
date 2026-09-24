package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

const rcodeNXDomain, rcodeServFail, rcodeRefused = 3, 2, 5

func newAuthority(t testing.TB, h *hierarchy, leaf *zone.Zone, opts ...memory.Option) *memory.Authority {
	t.Helper()
	all := append([]memory.Option{
		memory.WithZone(".", h.root),
		memory.WithZone("test.", h.tld),
		memory.WithZone("example.test.", leaf),
	}, opts...)
	a, err := memory.New(all...)
	if err != nil {
		t.Fatalf("memory.New: %v", err)
	}
	return a
}

func newVerifier(t testing.TB, h *hierarchy, a *memory.Authority, clock time.Time) *verifier.Verifier {
	t.Helper()
	anchors, err := signer.RootAnchors(h.rootKSK)
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.NewVerifier(
		verifier.WithResolver(a),
		verifier.WithTrustAnchors(anchors),
		verifier.WithClock(func() time.Time { return clock }),
	)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func validate(t *testing.T, v *verifier.Verifier, qname string, qtype uint16) *verifier.Result {
	t.Helper()
	res, err := v.Validate(context.Background(), qname, qtype)
	if err != nil {
		t.Fatalf("Validate(%s, %s): %v", qname, types.RRTypeName(qtype), err)
	}
	return res
}

// C-6 / C-8 / C-9 acceptance: a fake root is the trust anchor, and the
// in-memory authority answers every query the verifier makes.
func TestHierarchy_Verdicts(t *testing.T) {
	h := buildHierarchy(t)
	v := newVerifier(t, h, newAuthority(t, h, h.leaf), now)
	cases := []struct {
		name  string
		qname string
		qtype uint16
		want  verifier.Verdict
	}{
		{"positive answer", "www.example.test.", types.TypeA, verifier.VerdictSecure},
		{"apex answer", "example.test.", types.TypeSOA, verifier.VerdictSecure},
		{"type without a mnemonic", "key.example.test.", 65400, verifier.VerdictSecure},
		{"name does not exist", "nope.example.test.", types.TypeA, verifier.VerdictSecureNXDomain},
		{"type does not exist", "www.example.test.", types.TypeMX, verifier.VerdictSecureNoData},
		{"wildcard expansion", "x.wild.example.test.", types.TypeA, verifier.VerdictSecure},
		{"CNAME followed", "alias.example.test.", types.TypeA, verifier.VerdictSecure},
		{"unsigned delegation", "www.insecure.test.", types.TypeA, verifier.VerdictInsecure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := validate(t, v, tc.qname, tc.qtype)
			if res.Verdict != tc.want {
				t.Errorf("Verdict = %v (bogus %q at %q), want %v", res.Verdict, res.BogusReason, res.BogusAt, tc.want)
			}
		})
	}
}

// C-7: Result.Answer is the RRset that was validated — after a CNAME
// the target's RRset, for a wildcard the synthesised RRset at the query
// name, and for a type without a mnemonic its exact octets.
func TestHierarchy_Answer(t *testing.T) {
	h := buildHierarchy(t)
	v := newVerifier(t, h, newAuthority(t, h, h.leaf), now)
	cases := []struct {
		qname, wantName string
		qtype           uint16
		wantValue       string
		wantLabels      uint8
	}{
		{"alias.example.test.", "www.example.test.", types.TypeA, "192.0.2.10", 3},
		{"x.wild.example.test.", "x.wild.example.test.", types.TypeA, "192.0.2.20", 3},
		{"key.example.test.", "key.example.test.", 65400, `\# 35 030101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`, 3},
	}
	for _, tc := range cases {
		t.Run(tc.qname, func(t *testing.T) {
			res := validate(t, v, tc.qname, tc.qtype)
			a := res.Answer
			if res.Verdict != verifier.VerdictSecure || a == nil || len(a.Records) != 1 || len(a.Signatures) == 0 {
				t.Fatalf("Verdict %v, Answer %+v", res.Verdict, a)
			}
			if a.Name != tc.wantName || a.Records[0].Value != tc.wantValue {
				t.Errorf("Answer %s = %q, want %s = %q", a.Name, a.Records[0].Value, tc.wantName, tc.wantValue)
			}
			if a.Signatures[0].Labels != tc.wantLabels || !a.Signatures[0].Inception.Equal(inception) || !a.Signatures[0].Expiration.Equal(expiration) {
				t.Errorf("signature %+v", a.Signatures[0])
			}
		})
	}
	res := validate(t, v, "key.example.test.", 65400)
	if len(res.Answer.Records[0].RData) != 35 || res.Answer.Records[0].RData[0] != 3 {
		t.Errorf("TYPE65400 RDATA = %x", res.Answer.Records[0].RData)
	}
}

func TestHierarchy_TamperedRRsetIsBogus(t *testing.T) {
	h := buildHierarchy(t)
	tampered := &zone.Zone{}
	for _, rr := range h.leaf.AllRecords() {
		value := rr.Value
		if rr.Label == "www.example.test." && rr.Type == types.TypeA {
			value = "192.0.2.99"
		}
		if _, err := tampered.AddRRFromParts(rr.Label, rr.TTL, rr.Class, rr.Type, value); err != nil {
			t.Fatal(err)
		}
	}
	v := newVerifier(t, h, newAuthority(t, h, tampered), now)
	if res := validate(t, v, "www.example.test.", types.TypeA); res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %v, want Bogus", res.Verdict)
	}
}

func TestHierarchy_ExpiredSignatureIsBogus(t *testing.T) {
	h := buildHierarchy(t)
	expired := sign(t, h.leafUnsigned, "example.test.", h.leafKeys, inception, inception.Add(24*time.Hour))
	v := newVerifier(t, h, newAuthority(t, h, expired), now)
	res := validate(t, v, "www.example.test.", types.TypeA)
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %v, want Bogus", res.Verdict)
	}
}

// C-1 acceptance: a zone with a TYPE65400 RRset is read, signed, printed,
// read back, and still validates.
func TestHierarchy_PrintAndReadBack(t *testing.T) {
	h := buildHierarchy(t)
	text, err := h.leaf.PrintCanonical(0)
	if err != nil {
		t.Fatal(err)
	}
	reread := readZone(t, text)
	v := newVerifier(t, h, newAuthority(t, h, reread), now)
	if res := validate(t, v, "key.example.test.", 65400); res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %v (%s), want Secure", res.Verdict, res.BogusReason)
	}
}

func TestAuthority_FaultInjection(t *testing.T) {
	h := buildHierarchy(t)
	a := newAuthority(t, h, h.leaf, memory.WithFault("www.example.test.", types.TypeA, rcodeServFail))
	resp, err := a.Query(context.Background(), "www.example.test.", types.TypeA)
	if err != nil || resp.RCode != rcodeServFail || len(resp.Records) != 0 {
		t.Fatalf("faulted query = %+v, %v", resp, err)
	}
	v := newVerifier(t, h, a, now)
	res, err := v.Validate(context.Background(), "www.example.test.", types.TypeA)
	if !errors.Is(err, verifier.ErrResolver) {
		t.Errorf("Validate err = %v (result %+v), want ErrResolver", err, res)
	}
}

func TestAuthority_Answers(t *testing.T) {
	h := buildHierarchy(t)
	a := newAuthority(t, h, h.leaf)
	cases := []struct {
		name      string
		qname     string
		qtype     uint16
		rcode     uint8
		wantTypes map[uint16]int // type → count in the response
	}{
		{"answer with signature", "www.example.test.", types.TypeA, 0, map[uint16]int{types.TypeA: 1, types.TypeRRSIG: 1}},
		{"case and missing dot", "WWW.Example.Test", types.TypeA, 0, map[uint16]int{types.TypeA: 1, types.TypeRRSIG: 1}},
		{"DS answered by the parent", "example.test.", types.TypeDS, 0, map[uint16]int{types.TypeDS: 1, types.TypeRRSIG: 1}},
		{"DNSKEY answered by the child", "example.test.", types.TypeDNSKEY, 0, map[uint16]int{types.TypeDNSKEY: 2, types.TypeRRSIG: 1}},
		{"no DS at an unsigned delegation", "insecure.test.", types.TypeDS, 0, map[uint16]int{types.TypeNSEC: 1, types.TypeRRSIG: 1}},
		{"referral below an unsigned delegation", "www.insecure.test.", types.TypeA, 0, map[uint16]int{types.TypeNS: 1, types.TypeNSEC: 1, types.TypeRRSIG: 1}},
		{"NODATA", "www.example.test.", types.TypeMX, 0, map[uint16]int{types.TypeNSEC: 1, types.TypeRRSIG: 1}},
		{"NXDOMAIN", "nope.example.test.", types.TypeA, rcodeNXDomain, map[uint16]int{types.TypeNSEC: 2, types.TypeRRSIG: 2}},
		{"wildcard", "x.wild.example.test.", types.TypeA, 0, map[uint16]int{types.TypeA: 1, types.TypeNSEC: 1, types.TypeRRSIG: 2}},
		{"name in no delegated zone answered by the root", "example.", types.TypeA, rcodeNXDomain, map[uint16]int{types.TypeNSEC: 1}}, // one NSEC covers both example. and *.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := a.Query(context.Background(), tc.qname, tc.qtype)
			if err != nil {
				t.Fatal(err)
			}
			if resp.RCode != tc.rcode {
				t.Errorf("RCode = %d, want %d", resp.RCode, tc.rcode)
			}
			got := map[uint16]int{}
			for _, rr := range resp.Records {
				got[rr.Type]++
			}
			for typ, n := range tc.wantTypes {
				if got[typ] != n {
					t.Errorf("%d %s records, want %d (response %v)", got[typ], types.RRTypeName(typ), n, got)
				}
			}
		})
	}
}

func TestAuthority_RefusesNamesOutsideEveryZone(t *testing.T) {
	h := buildHierarchy(t)
	a, err := memory.New(memory.WithZone("example.test.", h.leaf))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.Query(context.Background(), "other.test.", types.TypeA)
	if err != nil || resp.RCode != rcodeRefused || len(resp.Records) != 0 {
		t.Errorf("Query outside = %+v, %v; want REFUSED", resp, err)
	}
}

// The synthesised A RRset and its RRSIG take the query name; the NSEC
// proving the next closer name keeps its own owner.
func TestAuthority_WildcardOwnerIsRewritten(t *testing.T) {
	h := buildHierarchy(t)
	resp, err := newAuthority(t, h, h.leaf).Query(context.Background(), "x.wild.example.test.", types.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	for _, rr := range resp.Records {
		covered := rr.Type
		if rr.Type == types.TypeRRSIG {
			sig, err := dnssec.ParseRRSig(nil, rr.Value)
			if err != nil {
				t.Fatal(err)
			}
			covered = sig.TypeCovered
		}
		if covered == types.TypeA && rr.Label != "x.wild.example.test." {
			t.Errorf("synthesised %s has owner %s", types.RRTypeName(rr.Type), rr.Label)
		}
		if covered == types.TypeNSEC && rr.Label != "*.wild.example.test." {
			t.Errorf("proof %s has owner %s", types.RRTypeName(rr.Type), rr.Label)
		}
	}
}

func TestAuthority_ReturnsCopies(t *testing.T) {
	h := buildHierarchy(t)
	a := newAuthority(t, h, h.leaf)
	first, _ := a.Query(context.Background(), "www.example.test.", types.TypeA)
	first.Records[0].Value = "192.0.2.200"
	second, _ := a.Query(context.Background(), "www.example.test.", types.TypeA)
	for _, rr := range second.Records {
		if rr.Type == types.TypeA && rr.Value != "192.0.2.10" {
			t.Error("a caller's change to a returned record leaked into the authority")
		}
	}
}

func TestAuthority_CanceledContext(t *testing.T) {
	h := buildHierarchy(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newAuthority(t, h, h.leaf).Query(ctx, "www.example.test.", types.TypeA); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestNew_Errors(t *testing.T) {
	h := buildHierarchy(t)
	cases := map[string][]memory.Option{
		"no zones":           nil,
		"relative apex":      {memory.WithZone("test", h.tld)},
		"duplicate apex":     {memory.WithZone("test.", h.tld), memory.WithZone("TEST.", h.tld)},
		"nil zone":           {memory.WithZone("test.", nil)},
		"record outside":     {memory.WithZone("example.test.", h.tld)},
		"fault without zone": {memory.WithFault("x.", types.TypeA, rcodeServFail)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := memory.New(opts...); err == nil {
				t.Error("want error")
			}
		})
	}
}
