package doh_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/resolver/doh"
	"github.com/shigeya/dnsdata-go/verifier"
)

// TestResolveSatisfiesVerifierResolver is a compile-time check that
// the [Client.Resolve] method value can be used directly as a
// [verifier.ResolverFunc]. If verifier's interface drifts (signature
// change), this test stops compiling, which is the desired outcome.
func TestResolveSatisfiesVerifierResolver(t *testing.T) {
	c := doh.NewClient()
	var _ verifier.Resolver = verifier.ResolverFunc(c.Resolve)
}
