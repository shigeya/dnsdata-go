package types

import "errors"

// Sentinel errors returned by the lookup functions in this package.
// Callers can use [errors.Is] to test against them.
//
// The TypeScript source throws bare [RangeError] for all unknown inputs,
// which forces callers to discriminate via message-string matching.
// Replacing that with typed sentinels is tracked as UF-003 in
// UPSTREAM_FEEDBACK.md.
var (
	ErrUnknownOpCode  = errors.New("unknown opcode")
	ErrUnknownRCode   = errors.New("unknown rcode")
	ErrUnknownRRType  = errors.New("unknown rr type")
	ErrUnknownRRClass = errors.New("unknown rr class")
	ErrUnknownAlgo    = errors.New("unknown dnssec algorithm")
)
