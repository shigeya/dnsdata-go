package verifier

import (
	"fmt"

	"github.com/shigeya/dnsdata-go/dnssec"
)

// Reason codes: the machine-readable cause in [Result.ReasonCode]. Each
// maps to a sentinel that [Result.Err] wraps (ErrBogus alone where none
// is named).
const (
	// CodeNoDS: Insecure delegation proven by NSEC / NSEC3 → [ErrNoDS].
	CodeNoDS = "no-ds"
	// CodeNoDNSKEY: a child zone with a DS has no DNSKEY → [ErrNoDNSKEY].
	CodeNoDNSKEY = "no-dnskey"
	// CodeTrustAnchorMismatch: no root KSK matches a trust anchor (or
	// none is configured) → [ErrTrustAnchorMismatch].
	CodeTrustAnchorMismatch = "trust-anchor-mismatch"
	// CodeDSMismatch: no child DNSKEY matches a parent DS → [ErrDSMismatch].
	CodeDSMismatch = "ds-mismatch"
	// CodeNoRRSIG: an rrset that must be signed has no RRSIG → [ErrSigInvalid].
	CodeNoRRSIG = "no-rrsig"
	// CodeNoMatchingKey: no DNSKEY matches the RRSIGs (signer, key tag)
	// or the key is not authenticated → [ErrSigInvalid].
	CodeNoMatchingKey = "no-matching-key"
	// CodeSigInvalid: a signature does not verify → [ErrSigInvalid].
	CodeSigInvalid = "sig-invalid"
	// CodeSigExpired: the clock is after the expiration → [ErrSigExpired].
	CodeSigExpired = "sig-expired"
	// CodeSigNotYetValid: the clock is before the inception → [ErrSigExpired].
	CodeSigNotYetValid = "sig-not-yet-valid"
	// CodeUnsupportedAlgorithm: every RRSIG uses an algorithm the
	// library does not implement → [ErrUnsupportedAlgo]. Set on the
	// Indeterminate Result that Validate returns with an [ErrVerifier]
	// error.
	CodeUnsupportedAlgorithm = "unsupported-algorithm"
	// CodeAliasLoop: a CNAME / DNAME chain revisits a name → ErrBogus.
	CodeAliasLoop = "alias-loop"
	// CodeAliasLimit: more than [MaxAliasHops] redirects → ErrBogus.
	CodeAliasLimit = "alias-limit"
	// CodeAliasTargetInvalid: a CNAME / DNAME target is empty or cannot
	// be synthesised → ErrBogus.
	CodeAliasTargetInvalid = "alias-target-invalid"
	// CodeWildcardProofMissing: a wildcard-synthesised answer lacks the
	// proof that the next closer name does not exist → ErrBogus.
	CodeWildcardProofMissing = "wildcard-proof-missing"
)

// codeSentinels maps a code to its sentinel; codes not listed map to
// ErrBogus alone.
var codeSentinels = map[string]error{
	CodeNoDS:                 ErrNoDS,
	CodeNoDNSKEY:             ErrNoDNSKEY,
	CodeTrustAnchorMismatch:  ErrTrustAnchorMismatch,
	CodeDSMismatch:           ErrDSMismatch,
	CodeNoRRSIG:              ErrSigInvalid,
	CodeNoMatchingKey:        ErrSigInvalid,
	CodeSigInvalid:           ErrSigInvalid,
	CodeSigExpired:           ErrSigExpired,
	CodeSigNotYetValid:       ErrSigExpired,
	CodeUnsupportedAlgorithm: ErrUnsupportedAlgo,
}

// Err returns the failure of the result as an error, or nil when
// ReasonCode is empty (Secure, SecureNoData, SecureNXDomain, and an
// Indeterminate without a known cause). The error wraps the code's
// sentinel and, for a Bogus verdict, [ErrBogus]; its text carries the
// failure point and human reason (BogusAt / BogusReason or InsecureAt /
// InsecureReason):
//
//	if errors.Is(res.Err(), verifier.ErrSigExpired) { … }
func (r *Result) Err() error {
	if r == nil || r.ReasonCode == "" {
		return nil
	}
	detail := r.failureDetail()
	sentinel, ok := codeSentinels[r.ReasonCode]
	switch {
	case !ok:
		return fmt.Errorf("%w: %s", ErrBogus, detail)
	case r.Verdict == VerdictBogus:
		return fmt.Errorf("%w: %w: %s", ErrBogus, sentinel, detail)
	}
	return fmt.Errorf("%w: %s", sentinel, detail)
}

// failureDetail renders "<code> at <zone>: <reason>" from the fields
// that go with the verdict.
func (r *Result) failureDetail() string {
	at, reason := r.BogusAt, r.BogusReason
	if r.Verdict == VerdictInsecure {
		at, reason = r.InsecureAt, r.InsecureReason
	}
	detail := r.ReasonCode
	if at != "" {
		detail += " at " + at
	}
	if reason != "" {
		detail += ": " + reason
	}
	return detail
}

// sigFailureOrder ranks RRSIG failures: the code of the first status
// present among an rrset's RRSIGs names the rrset's failure.
var sigFailureOrder = []struct {
	status dnssec.SigStatus
	code   string
}{
	{dnssec.SigExpired, CodeSigExpired},
	{dnssec.SigNotYetValid, CodeSigNotYetValid},
	{dnssec.SigInvalid, CodeSigInvalid},
	{dnssec.SigNoMatchingKey, CodeNoMatchingKey},
	{dnssec.SigUnsupportedAlgorithm, CodeUnsupportedAlgorithm},
}

// sigFailureCode names why an rrset whose RRSIGs are results did not
// verify. CodeUnsupportedAlgorithm comes out only when every RRSIG has
// an unsupported algorithm.
func sigFailureCode(results []dnssec.SigResult) string {
	if len(results) == 0 {
		return CodeNoRRSIG
	}
	for _, o := range sigFailureOrder {
		for _, r := range results {
			if r.Status == o.status {
				return o.code
			}
		}
	}
	return CodeSigInvalid
}

// rrsetCheck is the outcome of checking every RRSIG over one rrset.
type rrsetCheck struct {
	ok   bool
	code string     // why it failed, when !ok
	sigs []SigCheck // one per RRSIG examined
}

// checkRRSet verifies (name, rrtype) in z under mode with "any-valid"
// semantics (RFC 4035 §5.3.3), keeping each RRSIG's outcome. When the
// check cannot be carried out it returns an [ErrVerifier] error, as
// [dnssec.Zone.VerifyRRSet] callers always have; if the cause is an
// unsupported algorithm, result.ReasonCode records it.
func (v *Verifier) checkRRSet(z *dnssec.Zone, name string, rrtype uint16, mode dnssec.KeyVerifyMode, result *Result) (rrsetCheck, error) {
	results := z.CheckRRSet(name, rrtype, mode, "")
	ok, err := dnssec.RRSetVerified(results)
	c := rrsetCheck{ok: ok, sigs: sigChecks(name, results)}
	if !ok {
		c.code = sigFailureCode(results)
	}
	v.emitRRSetCheck(name, rrtype, c, err)
	if err != nil {
		if c.code == CodeUnsupportedAlgorithm {
			result.ReasonCode = c.code
		}
		return c, fmt.Errorf("%w: %v", ErrVerifier, err)
	}
	return c, nil
}

// bogusOutcome is the terminal hop outcome of a Bogus verdict.
func bogusOutcome(at, reason, code string) *hopOutcome {
	return &hopOutcome{Verdict: VerdictBogus, BogusAt: at, BogusReason: reason, ReasonCode: code}
}
