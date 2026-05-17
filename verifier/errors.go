package verifier

import "errors"

// Sentinel errors returned by [Verifier.Validate]. Callers can match
// them with [errors.Is].
//
// The set covers DESIGN.md §4 MUST 12: ErrNoDS, ErrSigExpired,
// ErrUnsupportedAlgo, ErrChainTimeout are spec-required names. Other
// errors group by failure mode so consumers (mailsec-probe Signals,
// future logging hooks) can render meaningful diagnoses without
// matching on free-text messages.
var (
	// ErrVerifier is the umbrella error wrapping every verifier-side
	// failure. Useful for `errors.Is(err, ErrVerifier)` checks at the
	// outer boundary.
	ErrVerifier = errors.New("verifier error")

	// ErrConfig is returned by [NewVerifier] when the supplied options
	// are inconsistent (e.g. no resolver supplied).
	ErrConfig = errors.New("verifier: invalid configuration")

	// ErrInvalidQName is returned by [Verifier.Validate] when qname is
	// empty or otherwise rejected by the wire encoder.
	ErrInvalidQName = errors.New("verifier: invalid qname")

	// ErrNoDS indicates a child zone reported no DS rrset at its
	// parent — i.e. the chain breaks at this point. Whether that is
	// Insecure (legitimately unsigned) or Bogus (DS expected but
	// missing) depends on the NSEC/NSEC3 proof in the parent's
	// response; v0.1.0 conservatively returns Bogus.
	ErrNoDS = errors.New("verifier: no DS records")

	// ErrNoDNSKEY indicates a zone returned no DNSKEY rrset. Always
	// Bogus when the parent's DS asserts the zone is signed.
	ErrNoDNSKEY = errors.New("verifier: no DNSKEY records")

	// ErrSigExpired indicates an RRSIG fell outside its validity
	// window (inception …
	// expire) when validated against the verifier's clock.
	ErrSigExpired = errors.New("verifier: RRSIG outside validity window")

	// ErrUnsupportedAlgo is returned when every available signature
	// uses a DNSSEC algorithm this verifier cannot implement
	// (e.g. Ed448, ECC-GOST).
	ErrUnsupportedAlgo = errors.New("verifier: unsupported algorithm")

	// ErrChainTimeout is returned when the supplied context's
	// deadline elapsed before the chain finished walking.
	ErrChainTimeout = errors.New("verifier: chain walk timed out")

	// ErrTrustAnchorMismatch indicates the root DNSKEY rrset does not
	// match any of the configured trust anchors (no DS digest
	// computed from a candidate KSK matches an anchor record).
	ErrTrustAnchorMismatch = errors.New("verifier: root KSK does not match any trust anchor")

	// ErrResolver is returned when the configured [Resolver] surfaces
	// an error (network, parse, etc.). The underlying cause is joined
	// via [errors.Join] so callers can still discriminate by inner
	// sentinel.
	ErrResolver = errors.New("verifier: resolver error")
)
