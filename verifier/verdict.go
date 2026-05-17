package verifier

import (
	"encoding/json"
	"fmt"
)

// Verdict is the outcome of DNSSEC chain validation, refining the
// four states in RFC 4033 §5 with two additional secure-negative
// states so callers can distinguish "secure absence of data" from
// "could not classify".
type Verdict uint8

const (
	// VerdictIndeterminate means validation could not be completed
	// (network failure, timeout, malformed response, unsupported
	// algorithm with no fallback). The result tells you nothing about
	// the security status of the data.
	VerdictIndeterminate Verdict = iota

	// VerdictSecure means a complete chain of signatures was
	// verified from a configured trust anchor to the requested rrset.
	VerdictSecure

	// VerdictSecureNoData means the chain reached a signed zone, the
	// qname exists, but the requested qtype does not — and the zone
	// produced a valid NSEC/NSEC3 proof of that absence (RFC 4035
	// §5.4 / RFC 5155 §8.5).
	VerdictSecureNoData

	// VerdictSecureNXDomain means the chain reached a signed zone,
	// the qname does not exist, and the zone produced a valid
	// NSEC/NSEC3 proof of that non-existence including the wildcard
	// non-existence proof (RFC 4035 §5.4 / RFC 5155 §8.4).
	VerdictSecureNXDomain

	// VerdictInsecure means the chain reached a zone that is
	// provably unsigned (NSEC/NSEC3 proof of no-DS from the parent),
	// and that zone signed the requested rrset only as cleartext —
	// no DNSSEC assertion is made.
	VerdictInsecure

	// VerdictBogus means signatures or chain links were present but
	// failed validation (expired RRSIGs, DS digest mismatch, missing
	// DNSKEY where DS asserts one exists, etc.).
	VerdictBogus
)

// String returns the lower-case mnemonic. The four RFC 4033 states
// keep their original spellings; the two secure-negative states use
// dash-separated names ("secure-nodata", "secure-nxdomain") so old
// consumers that only switch on the original four still see the
// canonical secure / insecure / bogus / indeterminate words at the
// front and can route the rest to a generic handler.
func (v Verdict) String() string {
	switch v {
	case VerdictSecure:
		return "secure"
	case VerdictSecureNoData:
		return "secure-nodata"
	case VerdictSecureNXDomain:
		return "secure-nxdomain"
	case VerdictInsecure:
		return "insecure"
	case VerdictBogus:
		return "bogus"
	case VerdictIndeterminate:
		return "indeterminate"
	}
	return fmt.Sprintf("verdict(%d)", uint8(v))
}

// MarshalJSON emits the lower-case mnemonic.
func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// UnmarshalJSON parses the lower-case mnemonic. Unknown values become
// [VerdictIndeterminate] so a future writer adding a new verdict does
// not crash older readers.
func (v *Verdict) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "secure":
		*v = VerdictSecure
	case "secure-nodata":
		*v = VerdictSecureNoData
	case "secure-nxdomain":
		*v = VerdictSecureNXDomain
	case "insecure":
		*v = VerdictInsecure
	case "bogus":
		*v = VerdictBogus
	default:
		*v = VerdictIndeterminate
	}
	return nil
}
