package verifier

import (
	"context"

	"github.com/shigeya/dnsdata-go/zone"
)

// Resolver is the transport-shaped dependency the chain walker uses
// to fetch DNSSEC data. Implementations are not required to perform
// any signature validation themselves; the verifier does that.
//
// Implementations:
//
//   - DoH backend (resolver/doh + a future response parser)
//   - Authoritative backend (resolver/auth, Week 3)
//   - In-memory fixture (used by this package's tests)
//
// Query semantics:
//
//   - name is presented in normalised dotted form (always
//     fully-qualified with a trailing dot, lowercased).
//   - The returned slice contains every record from the answer
//     section, including RRSIG records covering the answer rrset.
//     The verifier filters by type.
//   - An empty slice with a nil error means the name exists but the
//     rrset is empty (NODATA). For NXDOMAIN, return a typed error or
//     an empty slice; v0.1.0 treats both as "no records present".
//   - Network failures, parse failures, and other transport-level
//     problems should be returned as errors so [Verifier.Validate]
//     can convert them into [VerdictIndeterminate].
type Resolver interface {
	Query(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error)
}

// ResolverFunc adapts a plain function to the [Resolver] interface.
// Convenient for tests and one-off in-memory backends.
type ResolverFunc func(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error)

// Query implements [Resolver].
func (f ResolverFunc) Query(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error) {
	return f(ctx, name, qtype)
}
