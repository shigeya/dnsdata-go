package verifier

import (
	"fmt"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
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

// NewVerifier constructs a Verifier with the supplied options. A
// resolver is required.
//
// As a deliberate constructor-time side effect this also calls
// [dnssec.RegisterHandlers] so that the [zone.ResourceRecord] objects
// returned by the resolver materialise their DNSSEC handlers when
// the chain walker calls Handler(). DESIGN.md §4.21 forbids init()
// side effects but explicit construction is fine.
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
	dnssec.RegisterHandlers()
	return v, nil
}
