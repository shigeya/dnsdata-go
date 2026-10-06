package verifier

import (
	"fmt"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/zone"
)

// Verifier is the chain-of-trust walker. Construct with [NewVerifier].
//
// Instances hold no global state: every field is set once at
// construction and treated as read-only afterwards. Multiple
// Verifiers can run concurrently against different resolvers / trust
// anchors without interference (DESIGN.md MUST NOT 22).
type Verifier struct {
	resolver Resolver
	anchors  *dnssec.RootAnchors
	now      func() time.Time
	cache    Cache
	registry *zone.Registry
}

// Option configures a [Verifier] at construction time.
type Option func(*Verifier)

// WithResolver attaches the transport. A resolver is REQUIRED;
// [NewVerifier] returns [ErrConfig] if none is supplied.
func WithResolver(r Resolver) Option {
	return func(v *Verifier) { v.resolver = r }
}

// WithTrustAnchors overrides the built-in IANA root anchors. Useful
// for test setups that mint their own root KSK.
func WithTrustAnchors(a *dnssec.RootAnchors) Option {
	return func(v *Verifier) { v.anchors = a }
}

// WithClock overrides the source of "now" used to compare against
// RRSIG inception / expire windows. Tests freeze time; production
// callers normally do not need this option.
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) { v.now = now }
}

// WithCache attaches a pluggable [Cache] consulted before every
// resolver query. The cache is shared across Validate calls on the
// same Verifier, which is the intended way to reuse root / TLD
// DNSKEY rrsets across a batch run (DESIGN.md §4 SHOULD #13).
//
// Passing a nil Cache is equivalent to not setting the option:
// the verifier behaves as if no cache layer existed.
func WithCache(c Cache) Option {
	return func(v *Verifier) { v.cache = c }
}

// WithRegistry makes the Verifier resolve record handlers through reg
// instead of its own registry of the DNSSEC handlers. Use it to add
// handlers, e.g. the zone types:
//
//	reg := zone.NewRegistry()
//	dnssec.RegisterHandlersInto(reg)
//	zone.RegisterHandlersInto(reg)
//	v, err := verifier.NewVerifier(verifier.WithResolver(r), verifier.WithRegistry(reg))
//
// reg must hold the DNSSEC handlers ([dnssec.RegisterHandlersInto]) for
// validation to succeed. A nil reg is equivalent to not setting the
// option. Passing [zone.DefaultRegistry] shares the process-wide
// registry, and with it the handlers that [zone.ResourceRecord.Handler]
// returns.
func WithRegistry(reg *zone.Registry) Option {
	return func(v *Verifier) { v.registry = reg }
}

// NewVerifier constructs a Verifier with the supplied options. A
// resolver is required.
//
// The Verifier resolves record handlers through a [zone.Registry] it
// owns: by default a fresh one holding the DNSSEC handlers
// ([dnssec.RegisterHandlersInto]), or the one given with [WithRegistry].
// NewVerifier does not touch [zone.DefaultRegistry] (DESIGN.md MUST NOT
// 22). The zone handlers are not in the default set: an answer the
// resolver clients received (TLSA, SVCB, …) carries its RDATA octets,
// which sign as they are ([zone.NewResourceRecordWithRData]).
//
// Records are shared with the resolver and any [Cache]. A handler
// cached on a record is tied to the registry that built it
// ([zone.ResourceRecord.HandlerFrom]), so Verifiers with different
// registries sharing one cache stay independent.
func NewVerifier(opts ...Option) (*Verifier, error) {
	v := &Verifier{
		anchors: dnssec.BuiltinRootAnchors(),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.resolver == nil {
		return nil, fmt.Errorf("%w: WithResolver is required", ErrConfig)
	}
	if v.registry == nil {
		v.registry = zone.NewRegistry()
		dnssec.RegisterHandlersInto(v.registry)
	}
	return v, nil
}
