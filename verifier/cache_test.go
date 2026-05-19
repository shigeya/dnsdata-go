package verifier_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// countingResolver wraps a verifier.Resolver and increments a counter
// on every Query, so tests can assert how many times the underlying
// resolver was actually consulted.
type countingResolver struct {
	inner verifier.Resolver
	calls atomic.Int64
}

func (r *countingResolver) Query(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error) {
	r.calls.Add(1)
	return r.inner.Query(ctx, name, qtype)
}

// --- MemoryCache unit tests ---------------------------------------------

func TestMemoryCache_GetMissReturnsNotOK(t *testing.T) {
	c := verifier.NewMemoryCache()

	rrs, ok := c.Get("example.com.", types.TypeA)

	if ok {
		t.Errorf("Get on empty cache: ok = true, want false")
	}
	if rrs != nil {
		t.Errorf("Get on empty cache: rrs = %v, want nil", rrs)
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

func TestMemoryCache_RoundTrip(t *testing.T) {
	c := verifier.NewMemoryCache()
	rr, err := zone.NewResourceRecord("example.com.", 300, "IN", "A", "192.0.2.1")
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}
	records := []*zone.ResourceRecord{rr}

	c.Put("example.com.", types.TypeA, records)
	got, ok := c.Get("example.com.", types.TypeA)

	if !ok {
		t.Fatal("Get after Put: ok = false, want true")
	}
	if len(got) != 1 || got[0] != rr {
		t.Errorf("Get returned %v, want one record pointer-equal to the original", got)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

// NODATA (empty slice) MUST round-trip with ok=true so callers can
// distinguish "we asked and got nothing" from "we never asked".
func TestMemoryCache_NODATAIsHit(t *testing.T) {
	c := verifier.NewMemoryCache()
	c.Put("nodata.example.com.", types.TypeA, nil)

	got, ok := c.Get("nodata.example.com.", types.TypeA)

	if !ok {
		t.Errorf("Get of NODATA entry: ok = false, want true")
	}
	if len(got) != 0 {
		t.Errorf("Get of NODATA entry: got %d records, want 0", len(got))
	}
}

// Different qtypes at the same name are separate entries.
func TestMemoryCache_KeyedByNameAndType(t *testing.T) {
	c := verifier.NewMemoryCache()
	rrA, _ := zone.NewResourceRecord("example.com.", 300, "IN", "A", "192.0.2.1")
	rrAAAA, _ := zone.NewResourceRecord("example.com.", 300, "IN", "AAAA", "2001:db8::1")
	c.Put("example.com.", types.TypeA, []*zone.ResourceRecord{rrA})
	c.Put("example.com.", types.TypeAAAA, []*zone.ResourceRecord{rrAAAA})

	gotA, _ := c.Get("example.com.", types.TypeA)
	gotAAAA, _ := c.Get("example.com.", types.TypeAAAA)

	if len(gotA) != 1 || gotA[0] != rrA {
		t.Errorf("Get TypeA returned %v, want the A record", gotA)
	}
	if len(gotAAAA) != 1 || gotAAAA[0] != rrAAAA {
		t.Errorf("Get TypeAAAA returned %v, want the AAAA record", gotAAAA)
	}
}

// Concurrent Get and Put across many goroutines must not race or
// deadlock; -race is the real assertion. The counts are a smoke
// check that every writer left something behind.
func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	c := verifier.NewMemoryCache()
	const goroutines = 32
	const perGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				name := "n" + decUint(uint32(g*perGoroutine+i)) + ".example."
				c.Put(name, types.TypeA, nil)
				if _, ok := c.Get(name, types.TypeA); !ok {
					t.Errorf("Get after Put for %s: ok = false", name)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got, want := c.Len(), goroutines*perGoroutine; got != want {
		t.Errorf("Len = %d, want %d", got, want)
	}
}

// --- Integration with Verifier ------------------------------------------

// A second Validate on the same name with the same cache MUST NOT
// re-query any of the rrsets the first Validate already fetched.
func TestVerifier_WithCache_HitsAvoidResolverCalls(t *testing.T) {
	inner, anchors := buildChain(t)
	counting := &countingResolver{inner: inner}
	cache := verifier.NewMemoryCache()
	v, err := verifier.NewVerifier(
		verifier.WithResolver(counting),
		verifier.WithTrustAnchors(anchors),
		verifier.WithCache(cache),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	first, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if first.Verdict != verifier.VerdictSecure {
		t.Fatalf("first Verdict = %s, want secure", first.Verdict)
	}
	firstCalls := counting.calls.Load()
	if firstCalls == 0 {
		t.Fatal("first Validate did not call the resolver at all")
	}

	second, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if second.Verdict != verifier.VerdictSecure {
		t.Errorf("second Verdict = %s, want secure", second.Verdict)
	}
	if got := counting.calls.Load(); got != firstCalls {
		t.Errorf("resolver was called %d times on the cached run (delta %d), want 0", got-firstCalls, got-firstCalls)
	}
	if cache.Len() == 0 {
		t.Error("cache is empty after first Validate")
	}
}

// A second Validate against a different leaf in the same chain shares
// root + TLD lookups via the cache, even though the leaf itself is a
// miss.
func TestVerifier_WithCache_SharesAncestorLookups(t *testing.T) {
	inner, anchors := buildChain(t)
	counting := &countingResolver{inner: inner}
	cache := verifier.NewMemoryCache()
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(counting),
		verifier.WithTrustAnchors(anchors),
		verifier.WithCache(cache),
	)

	if _, err := v.Validate(context.Background(), "www.example.com.", types.TypeA); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	firstCalls := counting.calls.Load()

	// example.com./A is already in the chain fixture; reuse it as the
	// second target. Different qname → leaf lookups must happen, but
	// root and TLD DNSKEY/DS lookups must come from the cache.
	if _, err := v.Validate(context.Background(), "example.com.", types.TypeA); err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	delta := counting.calls.Load() - firstCalls
	if delta == 0 {
		t.Error("second Validate hit the cache for every record (expected at least a leaf miss)")
	}
	if delta >= firstCalls {
		t.Errorf("second Validate made %d resolver calls vs %d on the first (no cache reuse?)", delta, firstCalls)
	}
}

// A nil Cache passed via WithCache MUST behave exactly like no cache
// at all (no panics, no skipped queries).
func TestVerifier_WithCache_NilIsIgnored(t *testing.T) {
	inner, anchors := buildChain(t)
	counting := &countingResolver{inner: inner}
	v, err := verifier.NewVerifier(
		verifier.WithResolver(counting),
		verifier.WithTrustAnchors(anchors),
		verifier.WithCache(nil),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Validate(context.Background(), "www.example.com.", types.TypeA); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if counting.calls.Load() == 0 {
		t.Error("expected resolver to be called when WithCache(nil)")
	}
}
