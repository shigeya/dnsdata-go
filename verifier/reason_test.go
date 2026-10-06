package verifier_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// reasonFixture is the root → com. → example.com. chain of buildChain
// with its parts exposed, so a case can break one of them. The zones
// are signed from now-1h to now+24h; www.example.com./A is signed.
type reasonFixture struct {
	root, com, leaf *signedZone
	resp            map[lookupKey][]*zone.ResourceRecord
	inception       int64
	expire          int64
}

func newReasonFixture(t *testing.T) *reasonFixture {
	t.Helper()
	f := &reasonFixture{
		inception: time.Now().Add(-1 * time.Hour).Unix(),
		expire:    time.Now().Add(24 * time.Hour).Unix(),
	}
	f.root = newSignedZone(t, ".", f.inception, f.expire)
	f.com = newSignedZone(t, "com.", f.inception, f.expire)
	f.leaf = newSignedZone(t, "example.com.", f.inception, f.expire)
	addAndSignDS(t, f.root, "com.", f.com.key, f.inception, f.expire)
	addAndSignDS(t, f.com, "example.com.", f.leaf.key, f.inception, f.expire)
	f.leaf.addSignedRR(t, "www.example.com.", 300, types.TypeA, "192.0.2.10", f.inception, f.expire)
	f.resp = map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(f.root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(f.root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(f.com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(f.com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(f.leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeA}:  rrsetWithSigs(f.leaf.z, "www.example.com.", types.TypeA),
	}
	return f
}

// validate runs a Verifier over the fixture; opts come after the
// fixture's resolver and trust anchors, so they can override them.
func (f *reasonFixture) validate(t *testing.T, qname string, opts ...verifier.Option) (*verifier.Result, error) {
	t.Helper()
	all := append([]verifier.Option{
		verifier.WithResolver(&mockResolver{responses: f.resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, f.root.key)),
	}, opts...)
	v, err := verifier.NewVerifier(all...)
	if err != nil {
		t.Fatal(err)
	}
	return v.Validate(context.Background(), qname, types.TypeA)
}

// withoutRRSIGs returns rrs minus the RRSIG records.
func withoutRRSIGs(rrs []*zone.ResourceRecord) []*zone.ResourceRecord {
	var out []*zone.ResourceRecord
	for _, rr := range rrs {
		if rr.Type != types.TypeRRSIG {
			out = append(out, rr)
		}
	}
	return out
}

type reasonCase struct {
	name     string
	setup    func(t *testing.T, f *reasonFixture) (qname string, opts []verifier.Option)
	verdict  verifier.Verdict
	code     string
	sentinel error
	at       string
}

func at(clock time.Time) verifier.Option {
	return verifier.WithClock(func() time.Time { return clock })
}

var reasonCases = []reasonCase{
	{"expired", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		return "www.example.com.", []verifier.Option{at(time.Now().Add(48 * time.Hour))}
	}, verifier.VerdictBogus, verifier.CodeSigExpired, verifier.ErrSigExpired, "."},

	{"not yet valid", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		return "www.example.com.", []verifier.Option{at(time.Now().Add(-48 * time.Hour))}
	}, verifier.VerdictBogus, verifier.CodeSigNotYetValid, verifier.ErrSigExpired, "."},

	{"trust anchor mismatch", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		other := newSignedZone(t, ".", f.inception, f.expire)
		return "www.example.com.", []verifier.Option{verifier.WithTrustAnchors(makeTrustAnchor(t, other.key))}
	}, verifier.VerdictBogus, verifier.CodeTrustAnchorMismatch, verifier.ErrTrustAnchorMismatch, "."},

	{"DS mismatch", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		other := newSignedZone(t, "example.com.", f.inception, f.expire)
		f.resp[lookupKey{"example.com.", types.TypeDNSKEY}] = rrsetWithSigs(other.z, "example.com.", types.TypeDNSKEY)
		return "www.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeDSMismatch, verifier.ErrDSMismatch, "example.com."},

	{"no DNSKEY", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		f.resp[lookupKey{"example.com.", types.TypeDNSKEY}] = nil
		return "www.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeNoDNSKEY, verifier.ErrNoDNSKEY, "example.com."},

	{"invalid DS signature", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		tamperRRSIG(t, withRRSIGsOnly(f.resp[lookupKey{"com.", types.TypeDS}])[0])
		return "www.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeSigInvalid, verifier.ErrSigInvalid, "com."},

	{"invalid answer signature", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		tamperRRSIG(t, withRRSIGsOnly(f.resp[lookupKey{"www.example.com.", types.TypeA}])[0])
		return "www.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeSigInvalid, verifier.ErrSigInvalid, "example.com."},

	{"no RRSIG", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		key := lookupKey{"www.example.com.", types.TypeA}
		f.resp[key] = withoutRRSIGs(f.resp[key])
		return "www.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeNoRRSIG, verifier.ErrSigInvalid, "example.com."},

	{"no matching key", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		other := newSignedZone(t, "example.com.", f.inception, f.expire)
		other.addSignedRR(t, "www.example.com.", 300, types.TypeA, "192.0.2.10", f.inception, f.expire)
		key := lookupKey{"www.example.com.", types.TypeA}
		f.resp[key] = append(withoutRRSIGs(f.resp[key]),
			withRRSIGsOnly(rrsetWithSigs(other.z, "www.example.com.", types.TypeA))...)
		return "www.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeNoMatchingKey, verifier.ErrSigInvalid, "example.com."},

	{"no DS (insecure)", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		f.com.addSignedRR(t, "insecure.com.", 3600, types.TypeNSEC, "j.com. NS RRSIG NSEC", f.inception, f.expire)
		f.resp[lookupKey{"insecure.com.", types.TypeDS}] = nsecProof(f.com.z, "insecure.com.")
		return "www.insecure.com.", nil
	}, verifier.VerdictInsecure, verifier.CodeNoDS, verifier.ErrNoDS, "insecure.com."},

	{"alias loop", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		f.leaf.addSignedRR(t, "a.example.com.", 300, types.TypeCNAME, "b.example.com.", f.inception, f.expire)
		f.leaf.addSignedRR(t, "b.example.com.", 300, types.TypeCNAME, "a.example.com.", f.inception, f.expire)
		for _, n := range []string{"a.example.com.", "b.example.com."} {
			f.resp[lookupKey{n, types.TypeA}] = rrsetWithSigs(f.leaf.z, n, types.TypeCNAME)
		}
		return "a.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeAliasLoop, verifier.ErrBogus, "a.example.com."},

	{"alias limit", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		for i := 0; i <= verifier.MaxAliasHops+1; i++ {
			f.leaf.addSignedRR(t, chainName(i), 300, types.TypeCNAME, chainName(i+1), f.inception, f.expire)
			f.resp[lookupKey{chainName(i), types.TypeA}] = rrsetWithSigs(f.leaf.z, chainName(i), types.TypeCNAME)
		}
		return chainName(0), nil
	}, verifier.VerdictBogus, verifier.CodeAliasLimit, verifier.ErrBogus, chainName(verifier.MaxAliasHops + 1)},

	{"wildcard without proof", func(t *testing.T, f *reasonFixture) (string, []verifier.Option) {
		addWildcardSynthesisedRR(t, f.leaf, "foo.example.com.", 300, types.TypeA, "192.0.2.99", f.inception, f.expire, 2)
		f.resp[lookupKey{"foo.example.com.", types.TypeA}] = rrsetWithSigs(f.leaf.z, "foo.example.com.", types.TypeA)
		return "foo.example.com.", nil
	}, verifier.VerdictBogus, verifier.CodeWildcardProofMissing, verifier.ErrBogus, "example.com."},
}

// withRRSIGsOnly returns the RRSIG records of rrs.
func withRRSIGsOnly(rrs []*zone.ResourceRecord) []*zone.ResourceRecord {
	var out []*zone.ResourceRecord
	for _, rr := range rrs {
		if rr.Type == types.TypeRRSIG {
			out = append(out, rr)
		}
	}
	return out
}

func TestResult_ReasonCodes(t *testing.T) {
	for _, c := range reasonCases {
		t.Run(c.name, func(t *testing.T) {
			f := newReasonFixture(t)
			qname, opts := c.setup(t, f)
			res, err := f.validate(t, qname, opts...)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if res.Verdict != c.verdict || res.ReasonCode != c.code {
				t.Fatalf("verdict %s code %q, want %s %q (bogus %q at %q)",
					res.Verdict, res.ReasonCode, c.verdict, c.code, res.BogusReason, res.BogusAt)
			}
			failAt, reason := res.BogusAt, res.BogusReason
			if c.verdict == verifier.VerdictInsecure {
				failAt, reason = res.InsecureAt, res.InsecureReason
			}
			if failAt != c.at {
				t.Errorf("failed at %q, want %q", failAt, c.at)
			}
			rerr := res.Err()
			if !errors.Is(rerr, c.sentinel) {
				t.Errorf("Err() = %v, want it to wrap %v", rerr, c.sentinel)
			}
			if c.verdict == verifier.VerdictBogus && !errors.Is(rerr, verifier.ErrBogus) {
				t.Errorf("Err() = %v, want it to wrap ErrBogus", rerr)
			}
			if rerr != nil && !strings.Contains(rerr.Error(), reason) {
				t.Errorf("Err() = %q, want it to carry the reason %q", rerr, reason)
			}
		})
	}
}

// TestResult_UnsupportedAlgorithm pins today's behaviour for an answer
// signed only with an algorithm the library does not implement
// (Ed448): Validate fails with ErrVerifier and an Indeterminate result,
// whose ReasonCode and Err() name the cause.
func TestResult_UnsupportedAlgorithm(t *testing.T) {
	f := newReasonFixture(t)
	keyData := make([]byte, 57)
	if _, err := rand.Read(keyData); err != nil {
		t.Fatal(err)
	}
	fake := dnssec.NewDNSKey(nil, 256, 3, 16, keyData)
	f.leaf.addSignedRR(t, "example.com.", 3600, types.TypeDNSKEY,
		"256 3 16 "+base64.StdEncoding.EncodeToString(keyData), f.inception, f.expire)
	f.resp[lookupKey{"example.com.", types.TypeDNSKEY}] = rrsetWithSigs(f.leaf.z, "example.com.", types.TypeDNSKEY)

	sig := make([]byte, 114)
	if _, err := rand.Read(sig); err != nil {
		t.Fatal(err)
	}
	rrsig, err := zone.NewResourceRecord("www.example.com.", 300, "IN", "RRSIG", joinSpace(
		"A 16 3 300", decUint(uint32(f.expire)), decUint(uint32(f.inception)), decUint(fake.KeyTag),
		"example.com.", base64.StdEncoding.EncodeToString(sig)))
	if err != nil {
		t.Fatal(err)
	}
	key := lookupKey{"www.example.com.", types.TypeA}
	f.resp[key] = append(withoutRRSIGs(f.resp[key]), rrsig)

	res, err := f.validate(t, "www.example.com.")
	if !errors.Is(err, verifier.ErrVerifier) {
		t.Fatalf("Validate error %v, want ErrVerifier", err)
	}
	if res.Verdict != verifier.VerdictIndeterminate || res.ReasonCode != verifier.CodeUnsupportedAlgorithm {
		t.Fatalf("verdict %s code %q, want indeterminate %q", res.Verdict, res.ReasonCode, verifier.CodeUnsupportedAlgorithm)
	}
	if !errors.Is(res.Err(), verifier.ErrUnsupportedAlgo) {
		t.Errorf("Err() = %v, want it to wrap ErrUnsupportedAlgo", res.Err())
	}
}

func TestResult_ErrNilWithoutFailure(t *testing.T) {
	f := newReasonFixture(t)
	res, err := f.validate(t, "www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != verifier.VerdictSecure || res.ReasonCode != "" || res.Err() != nil {
		t.Errorf("verdict %s code %q Err %v, want secure, no code, nil", res.Verdict, res.ReasonCode, res.Err())
	}
}
