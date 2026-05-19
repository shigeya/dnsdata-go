package verifier

import (
	"context"

	"github.com/shigeya/dnsdata-go/resolver"
)

// Resolver is the transport-shaped dependency the chain walker uses
// to fetch DNSSEC data. Implementations are not required to perform
// any signature validation themselves; the verifier does that.
//
// Implementations:
//
//   - DoH backend (resolver/doh)
//   - Authoritative backend (resolver/auth)
//   - In-memory fixture (used by this package's tests)
//
// Query semantics:
//
//   - name is presented in normalised dotted form (always
//     fully-qualified with a trailing dot, lowercased).
//   - The returned [resolver.Response] carries every record from the
//     answer and authority sections (including RRSIG records covering
//     the answer rrset); the verifier filters by type.
//   - An empty Records slice with a nil error means the name exists
//     but the rrset is empty (NODATA). For NXDOMAIN the response
//     should set RCode = 3 (or return empty records — v0.1.0 treats
//     both as "no records present").
//   - Non-zero RCODE values are surfaced via [resolver.Response.RCode],
//     not as errors. The verifier classifies them itself.
//   - Network failures, parse failures, and other transport-level
//     problems should be returned as errors so [Verifier.Validate]
//     can convert them into [VerdictIndeterminate].
type Resolver interface {
	Query(ctx context.Context, name string, qtype uint16) (resolver.Response, error)
}

// ResolverFunc adapts a plain function to the [Resolver] interface.
// Convenient for tests and one-off in-memory backends.
type ResolverFunc func(ctx context.Context, name string, qtype uint16) (resolver.Response, error)

// Query implements [Resolver].
func (f ResolverFunc) Query(ctx context.Context, name string, qtype uint16) (resolver.Response, error) {
	return f(ctx, name, qtype)
}
