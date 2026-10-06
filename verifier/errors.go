package verifier

import "errors"

// Sentinel errors of the verifier. Callers match them with [errors.Is].
//
// They reach the caller in two ways (DESIGN.md §4 MUST 12):
//
//   - Returned by [NewVerifier] / [Verifier.Validate] when no verdict
//     could be formed: [ErrConfig], [ErrInvalidQName], [ErrResolver],
//     [ErrChainTimeout], [ErrVerifier].
//   - Through [Result.Err] when the verdict is a classified failure
//     (Bogus, Insecure, or the Indeterminate of an unsupported
//     algorithm): [ErrBogus], [ErrNoDS], [ErrNoDNSKEY],
//     [ErrTrustAnchorMismatch], [ErrDSMismatch], [ErrSigExpired],
//     [ErrSigInvalid], [ErrUnsupportedAlgo]. Validate itself never
//     returns these: Bogus and Insecure are verdicts, not errors. Each
//     [Result.ReasonCode] maps to one of them (see the Code constants).
var (
	// ErrVerifier is the umbrella error wrapping every verifier-side
	// failure. Useful for `errors.Is(err, ErrVerifier)` checks at the
	// outer boundary. Returned by Validate.
	ErrVerifier = errors.New("verifier error")

	// ErrConfig is returned by [NewVerifier] when the supplied options
	// are inconsistent (e.g. no resolver supplied).
	ErrConfig = errors.New("verifier: invalid configuration")

	// ErrInvalidQName is returned by [Verifier.Validate] when qname is
	// empty or otherwise rejected by the wire encoder.
	ErrInvalidQName = errors.New("verifier: invalid qname")

	// ErrBogus is wrapped by [Result.Err] for every Bogus verdict,
	// together with the code's own sentinel when it has one.
	ErrBogus = errors.New("verifier: bogus")

	// ErrNoDS ([CodeNoDS], via [Result.Err]): the parent proved with
	// NSEC / NSEC3 that a child zone has no DS rrset, so the chain
	// ends there and the verdict is Insecure.
	ErrNoDS = errors.New("verifier: no DS records")

	// ErrNoDNSKEY ([CodeNoDNSKEY], via [Result.Err]): a zone whose
	// parent holds a DS returned no DNSKEY rrset. Bogus.
	ErrNoDNSKEY = errors.New("verifier: no DNSKEY records")

	// ErrSigExpired ([CodeSigExpired] and [CodeSigNotYetValid], via
	// [Result.Err]): an RRSIG fell outside its validity window
	// (inception … expiration) at the verifier's clock. Bogus.
	ErrSigExpired = errors.New("verifier: RRSIG outside validity window")

	// ErrSigInvalid ([CodeSigInvalid], [CodeNoMatchingKey] and
	// [CodeNoRRSIG], via [Result.Err]): no RRSIG over an rrset verified
	// because the signature did not verify, no key matched it, or there
	// was none. Bogus.
	ErrSigInvalid = errors.New("verifier: no valid RRSIG")

	// ErrUnsupportedAlgo ([CodeUnsupportedAlgorithm], via [Result.Err]):
	// every signature over an rrset uses a DNSSEC algorithm this
	// verifier does not implement (e.g. Ed448, ECC-GOST). Validate then
	// returns an [ErrVerifier] error together with an Indeterminate
	// Result that carries this code.
	ErrUnsupportedAlgo = errors.New("verifier: unsupported algorithm")

	// ErrChainTimeout is returned when the supplied context's
	// deadline elapsed before the chain finished walking.
	ErrChainTimeout = errors.New("verifier: chain walk timed out")

	// ErrTrustAnchorMismatch ([CodeTrustAnchorMismatch], via
	// [Result.Err]): the root DNSKEY rrset does not match any of the
	// configured trust anchors (no DS digest computed from a candidate
	// KSK matches an anchor record). Bogus.
	ErrTrustAnchorMismatch = errors.New("verifier: root KSK does not match any trust anchor")

	// ErrDSMismatch ([CodeDSMismatch], via [Result.Err]): no DNSKEY of
	// a child zone matches a DS record at its parent. Bogus.
	ErrDSMismatch = errors.New("verifier: no DNSKEY matches a DS")

	// ErrResolver is returned when the configured [Resolver] surfaces
	// an error (network, parse, etc.). The underlying cause is joined
	// via [errors.Join] so callers can still discriminate by inner
	// sentinel.
	ErrResolver = errors.New("verifier: resolver error")
)
