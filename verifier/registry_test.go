package verifier_test

import (
	"context"
	"sync"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// markerHandler is what the sentinel factory below builds.
type markerHandler struct{ zone.RecordHandler }

func markerFactory(*zone.ResourceRecord, string) zone.RecordHandler { return markerHandler{} }

// TestNewVerifier_LeavesDefaultRegistryUntouched installs a sentinel
// DNSKEY factory in the default registry and checks NewVerifier does
// not replace it (MUST NOT 22: no global state).
func TestNewVerifier_LeavesDefaultRegistryUntouched(t *testing.T) {
	def := zone.DefaultRegistry()
	prev := def.Lookup(types.TypeDNSKEY)
	def.Register(types.TypeDNSKEY, markerFactory)
	t.Cleanup(func() { def.Register(types.TypeDNSKEY, prev) })

	if _, err := verifier.NewVerifier(verifier.WithResolver(verifier.ResolverFunc(nil))); err != nil {
		t.Fatal(err)
	}
	f := def.Lookup(types.TypeDNSKEY)
	if f == nil {
		t.Fatal("NewVerifier removed the DNSKEY factory from the default registry")
	}
	if _, ok := f(nil, "").(markerHandler); !ok {
		t.Error("NewVerifier replaced the DNSKEY factory in the default registry")
	}
}

// TestVerifier_RegistriesAreIndependent runs, concurrently and over one
// shared cache, a Verifier with the default DNSSEC registry and one
// whose registry knows no DNSSEC type: the first validates, the second
// cannot read the root DNSKEYs, and neither affects the other.
func TestVerifier_RegistriesAreIndependent(t *testing.T) {
	resolver, anchors := buildChain(t)
	cache := verifier.NewMemoryCache()
	good, err := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors),
		verifier.WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	blind, err := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors),
		verifier.WithCache(cache), verifier.WithRegistry(zone.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	// Prime the cache so the goroutines below do not race on the
	// mock resolver.
	if _, err := good.Validate(context.Background(), "www.example.com.", types.TypeA); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, want := good, verifier.VerdictSecure
			if i%2 == 1 {
				v, want = blind, verifier.VerdictBogus
			}
			res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
			if err != nil {
				t.Error(err)
				return
			}
			if res.Verdict != want {
				t.Errorf("verifier %d: verdict %s, want %s (%s)", i%2, res.Verdict, want, res.BogusReason)
			}
		}()
	}
	wg.Wait()
}
