package types

import (
	"errors"
	"fmt"
)

// OPKEYMnemonic is the mnemonic of the OPKEY RR type
// (draft-shigeya-dns-opkey-00).
const OPKEYMnemonic = "OPKEY"

// opkeyTypeValue is the OPKEY type value. IANA has not allocated one
// yet, and [TypeInvalid] stands for "not allocated".
//
// It is unexported on purpose: 0 is already [TypeInvalid] in this
// package (and "every type" to zone.Zone.Print), so an exported
// TypeOPKEY = 0 would silently alias it. Callers get the value through
// [OPKEYType], which fails until the value is allocated. When it is,
// this constant is the only line to change: [StringToRRType],
// [RRTypeToString] and [QTypeValidForRequest] all consult it.
//
// Never set it to a private-use value (65280-65534): the draft rules
// that out for the public experiment (draft §4.1).
const opkeyTypeValue uint16 = TypeInvalid

// ErrOPKEYTypeUnallocated is returned by [OPKEYType], and by
// [StringToRRType] for the mnemonic "OPKEY", while the OPKEY type
// value is not allocated. Until then OPKEY RDATA is published as a
// TLSA RRset (draft §4.1). From StringToRRType it also wraps
// [ErrUnknownRRType], so callers that test for that keep working.
var ErrOPKEYTypeUnallocated = errors.New("OPKEY type value not allocated; publish the TLSA form")

// OPKEYType returns the OPKEY type value, or [ErrOPKEYTypeUnallocated]
// while IANA has not allocated one. Code that would put OPKEY on the
// wire (a query, an RR) takes the value from here, so it cannot send
// type 0 by accident.
func OPKEYType() (uint16, error) {
	if !opkeyAllocated() {
		return 0, ErrOPKEYTypeUnallocated
	}
	return opkeyTypeValue, nil
}

func opkeyAllocated() bool { return opkeyTypeValue != TypeInvalid }

// isOPKEYType reports whether t is the allocated OPKEY type value.
// Always false while the value is not allocated.
func isOPKEYType(t uint16) bool { return opkeyAllocated() && t == opkeyTypeValue }

// opkeyFromMnemonic is the "OPKEY" branch of [StringToRRType].
func opkeyFromMnemonic() (uint16, error) {
	t, err := OPKEYType()
	if err != nil {
		return 0, fmt.Errorf("%w (%w)", err, ErrUnknownRRType)
	}
	return t, nil
}
