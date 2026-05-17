package types

import "fmt"

// OpCode constants per RFC 1035 / 1996 / 2136.
const (
	OpCodeQuery  uint8 = 0
	OpCodeIQuery uint8 = 1 // deprecated, RFC 3425
	OpCodeStatus uint8 = 2
	// opcode 3 is reserved
	OpCodeNotify uint8 = 4 // RFC 1996
	OpCodeUpdate uint8 = 5 // RFC 2136
)

// OpCodeToString returns the canonical mnemonic for opcode, or wraps
// [ErrUnknownOpCode] for any value not assigned by IANA.
func OpCodeToString(opcode uint8) (string, error) {
	switch opcode {
	case OpCodeQuery:
		return "Query", nil
	case OpCodeIQuery:
		return "IQuery", nil
	case OpCodeStatus:
		return "Status", nil
	case OpCodeNotify:
		return "Notify", nil
	case OpCodeUpdate:
		return "Update", nil
	}
	return "", fmt.Errorf("%w: %d", ErrUnknownOpCode, opcode)
}

// StringToOpCode is the inverse of [OpCodeToString].
func StringToOpCode(s string) (uint8, error) {
	switch s {
	case "Query":
		return OpCodeQuery, nil
	case "IQuery":
		return OpCodeIQuery, nil
	case "Status":
		return OpCodeStatus, nil
	case "Notify":
		return OpCodeNotify, nil
	case "Update":
		return OpCodeUpdate, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownOpCode, s)
}
