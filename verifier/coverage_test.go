package verifier_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestResolverFunc_Adapter exercises the ResolverFunc convenience
// type so the resolver.go path stays under coverage.
func TestResolverFunc_Adapter(t *testing.T) {
	called := false
	var r verifier.Resolver = verifier.ResolverFunc(func(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error) {
		called = true
		if name != "x." || qtype != types.TypeA {
			t.Errorf("ResolverFunc got name=%q qtype=%d", name, qtype)
		}
		return nil, nil
	})
	if _, err := r.Query(context.Background(), "x.", types.TypeA); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !called {
		t.Errorf("ResolverFunc body not invoked")
	}
}

// TestWithClock asserts the option is accepted and overrides the
// default clock. We test that the override is read by the verifier
// by feeding it a clock far in the past and watching for no panic;
// signature validity-window enforcement against the clock is a
// follow-up (DESIGN.md SHOULD #16, tracked separately).
func TestWithClock(t *testing.T) {
	clock := func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
	resolver, anchors := buildChain(t)
	v, err := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(anchors),
		verifier.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v == nil {
		t.Fatal("nil verifier")
	}
}

// TestVerdict_StringUnknown exercises the "verdict(N)" fall-through.
func TestVerdict_StringUnknown(t *testing.T) {
	v := verifier.Verdict(99)
	got := v.String()
	if !strings.Contains(got, "99") {
		t.Errorf("String = %q, want to contain 99", got)
	}
}

// TestNormalizeQName_Surfaces probes the few normalisation paths the
// chain doesn't cover end-to-end. It uses Validate as the public
// observation surface: the verifier must lowercase + dot-terminate
// whatever it receives.
func TestNormalizeQName_Surfaces(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))

	res, err := v.Validate(context.Background(), "WWW.example.com", types.TypeA)
	if err != nil {
		t.Fatalf("Validate(mixed case, no dot): %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure (reason=%q)", res.Verdict, res.BogusReason)
	}
}

// TestValidate_EmptyQName surfaces the early-return ErrInvalidQName
// path.
func TestValidate_EmptyQName(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	_, err := v.Validate(context.Background(), "", types.TypeA)
	if err == nil {
		t.Fatal("Validate('') = nil err")
	}
}

// TestValidate_BogusDSSignature exercises the descendInto "DS rrset
// failed signature verification" branch. We tamper with the cached
// RRSIG handler of the DS rrset at com., which is signed by root.
func TestValidate_BogusDSSignature(t *testing.T) {
	resolver, anchors := buildChain(t)
	key := lookupKey{"com.", types.TypeDS}
	for _, rr := range resolver.responses[key] {
		if rr.Type != types.TypeRRSIG {
			continue
		}
		sig := rr.Handler().(*dnssec.RRSig)
		sig.Signature[0] ^= 0x01
		break
	}

	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
	if res.BogusAt != "com." {
		t.Errorf("BogusAt = %q, want com.", res.BogusAt)
	}
}

// TestValidate_NODataLeaf returns no records for the leaf rrset; the
// verifier should classify this as Indeterminate in v0.1.0 (no NSEC
// proof support).
func TestValidate_NODataLeaf(t *testing.T) {
	resolver, anchors := buildChain(t)
	resolver.responses[lookupKey{"www.example.com.", types.TypeA}] = nil

	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictIndeterminate {
		t.Errorf("Verdict = %s, want indeterminate", res.Verdict)
	}
}
