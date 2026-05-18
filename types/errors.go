package types

import "errors"

// Sentinel errors returned by the lookup functions in this package.
// Callers can use [errors.Is] to test against them.
var (
	ErrUnknownOpCode  = errors.New("unknown opcode")
	ErrUnknownRCode   = errors.New("unknown rcode")
	ErrUnknownRRType  = errors.New("unknown rr type")
	ErrUnknownRRClass = errors.New("unknown rr class")
	ErrUnknownAlgo    = errors.New("unknown dnssec algorithm")
)
