package types

import "fmt"

// RR class constants per IANA DNS CLASSes registry.
const (
	ClassInvalid uint16 = 0
	ClassIN      uint16 = 1 // Internet
	// 2 is unassigned; the TypeScript source preserves it as "UNALLOC_2"
	// for round-trip fidelity.
	ClassUnalloc2 uint16 = 2
	ClassCHAOS    uint16 = 3
	ClassHS       uint16 = 4 // Hesiod
	// Query-only classes (never appear in actual RRs)
	ClassNONE uint16 = 254
	ClassANY  uint16 = 255
)

// RRClassToString returns the canonical mnemonic for a class code, or
// wraps [ErrUnknownRRClass] for any unassigned value.
func RRClassToString(c uint16) (string, error) {
	switch c {
	case ClassInvalid:
		return "INVALID", nil
	case ClassIN:
		return "IN", nil
	case ClassUnalloc2:
		return "UNALLOC_2", nil
	case ClassCHAOS:
		return "CHAOS", nil
	case ClassHS:
		return "HS", nil
	case ClassNONE:
		return "NONE", nil
	case ClassANY:
		return "ANY", nil
	}
	return "", fmt.Errorf("%w: %d", ErrUnknownRRClass, c)
}

// StringToRRClass is the inverse of [RRClassToString].
func StringToRRClass(s string) (uint16, error) {
	switch s {
	case "INVALID":
		return ClassInvalid, nil
	case "IN":
		return ClassIN, nil
	case "UNALLOC_2":
		return ClassUnalloc2, nil
	case "CHAOS":
		return ClassCHAOS, nil
	case "HS":
		return ClassHS, nil
	case "NONE":
		return ClassNONE, nil
	case "ANY":
		return ClassANY, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownRRClass, s)
}

// QClassValidForRequest reports whether c is acceptable in the qclass
// field of a DNS request. INVALID and NONE return false.
func QClassValidForRequest(c uint16) bool {
	switch c {
	case ClassIN, ClassCHAOS, ClassHS, ClassANY:
		return true
	}
	return false
}
