package verifier

import (
	"encoding/json"
	"fmt"
)

// Verdict is the four-state outcome of DNSSEC chain validation
// (RFC 4033 §5).
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

// String returns the lower-case mnemonic spelled out by RFC 4033 and
// asserted in DESIGN.md MUST 11.
func (v Verdict) String() string {
	switch v {
	case VerdictSecure:
		return "secure"
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
	case "insecure":
		*v = VerdictInsecure
	case "bogus":
		*v = VerdictBogus
	default:
		*v = VerdictIndeterminate
	}
	return nil
}
