package verifier_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
)

// collect validates qname over f with a step handler and returns the
// result and the events seen. It fails the test if the handler runs
// after Validate returned.
func collect(t *testing.T, f *reasonFixture, qname string, opts ...verifier.Option) (*verifier.Result, []verifier.StepEvent) {
	t.Helper()
	var events []verifier.StepEvent
	var returned atomic.Bool
	handler := func(e verifier.StepEvent) {
		if returned.Load() {
			t.Error("step handler called after Validate returned")
		}
		events = append(events, e)
	}
	res, err := f.validate(t, qname, append(opts, verifier.WithStepHandler(handler))...)
	returned.Store(true)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return res, events
}

func eventsOf(events []verifier.StepEvent, kind string) []verifier.StepEvent {
	var out []verifier.StepEvent
	for _, e := range events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestStepHandler_SecureChain(t *testing.T) {
	f := newReasonFixture(t)
	res, events := collect(t, f, "www.example.com.")

	var zones []string
	for _, e := range eventsOf(events, verifier.StepZone) {
		zones = append(zones, e.Zone)
	}
	if want := []string{".", "com.", "example.com."}; !equalStrings(zones, want) {
		t.Errorf("zone events %v, want %v (root to leaf)", zones, want)
	}

	// One sig event per SigCheck, in chain order for a single hop.
	var chainSigs []verifier.SigCheck
	var chainZones []string
	for _, step := range res.Chain {
		for _, s := range step.Signatures {
			chainSigs = append(chainSigs, s)
			chainZones = append(chainZones, step.Zone)
		}
	}
	sigs := eventsOf(events, verifier.StepSig)
	if len(sigs) != len(chainSigs) {
		t.Fatalf("%d sig events, %d SigChecks in the chain", len(sigs), len(chainSigs))
	}
	for i, e := range sigs {
		if e.Sig == nil || *e.Sig != chainSigs[i] || e.Zone != chainZones[i] {
			t.Errorf("sig event %d = %s %+v, want %s %+v", i, e.Zone, e.Sig, chainZones[i], chainSigs[i])
		}
	}

	for _, kind := range []string{verifier.StepQuery, verifier.StepDS, verifier.StepDNSKEY} {
		if len(eventsOf(events, kind)) == 0 {
			t.Errorf("no %s event", kind)
		}
	}
	last := events[len(events)-1]
	if last.Kind != verifier.StepAnswer || last.Detail != "secure" {
		t.Errorf("last event %+v, want answer secure", last)
	}
}

func TestStepHandler_AliasAndBogus(t *testing.T) {
	f := newReasonFixture(t)
	f.leaf.addSignedRR(t, "alias.example.com.", 300, types.TypeCNAME, "www.example.com.", f.inception, f.expire)
	f.resp[lookupKey{"alias.example.com.", types.TypeA}] = rrsetWithSigs(f.leaf.z, "alias.example.com.", types.TypeCNAME)
	tamperRRSIG(t, withRRSIGsOnly(f.resp[lookupKey{"www.example.com.", types.TypeA}])[0])

	res, events := collect(t, f, "alias.example.com.")
	if res.Verdict != verifier.VerdictBogus {
		t.Fatalf("verdict %s, want bogus", res.Verdict)
	}
	if a := eventsOf(events, verifier.StepAlias); len(a) != 1 || a[0].Zone != "example.com." {
		t.Errorf("alias events %+v, want one in example.com.", a)
	}
	b := eventsOf(events, verifier.StepBogus)
	if len(b) != 1 || b[0].Zone != res.BogusAt {
		t.Errorf("bogus events %+v, want one at %s", b, res.BogusAt)
	}
	total := 0
	for _, step := range res.Chain {
		total += len(step.Signatures)
	}
	if n := len(eventsOf(events, verifier.StepSig)); n != total {
		t.Errorf("%d sig events over two hops, %d SigChecks in the chain", n, total)
	}
}

func TestStepHandler_CacheHit(t *testing.T) {
	f := newReasonFixture(t)
	cache := verifier.NewMemoryCache()
	collect(t, f, "www.example.com.", verifier.WithCache(cache))
	_, events := collect(t, f, "www.example.com.", verifier.WithCache(cache))
	if len(eventsOf(events, verifier.StepCacheHit)) == 0 || len(eventsOf(events, verifier.StepQuery)) != 0 {
		t.Errorf("second run: %d cache-hit and %d query events, want hits only",
			len(eventsOf(events, verifier.StepCacheHit)), len(eventsOf(events, verifier.StepQuery)))
	}
}

func TestStepHandler_NilIsNoOp(t *testing.T) {
	f := newReasonFixture(t)
	res, err := f.validate(t, "www.example.com.", verifier.WithStepHandler(nil))
	if err != nil || res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Validate: %v, %v", res.Verdict, err)
	}
}

func TestStepHandler_Insecure(t *testing.T) {
	f := newReasonFixture(t)
	f.com.addSignedRR(t, "insecure.com.", 3600, types.TypeNSEC, "j.com. NS RRSIG NSEC", f.inception, f.expire)
	f.resp[lookupKey{"insecure.com.", types.TypeDS}] = nsecProof(f.com.z, "insecure.com.")
	_, events := collect(t, f, "www.insecure.com.")
	if e := eventsOf(events, verifier.StepInsecure); len(e) != 1 || e[0].Zone != "insecure.com." {
		t.Errorf("insecure events %+v, want one at insecure.com.", e)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestStepHandler_NotCalledAfterError checks that a Validate call that
// fails (here on a cancelled context) emits nothing after it returns.
func TestStepHandler_NotCalledAfterError(t *testing.T) {
	f := newReasonFixture(t)
	var returned atomic.Bool
	v, err := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: f.resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, f.root.key)),
		verifier.WithStepHandler(func(verifier.StepEvent) {
			if returned.Load() {
				t.Error("step handler called after Validate returned")
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = v.Validate(ctx, "www.example.com.", types.TypeA)
	returned.Store(true)
}
