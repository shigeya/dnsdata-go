package types

import (
	"strconv"
	"strings"
)

// RFC 3597 §5 generic mnemonics: any RR type may be written as
// `TYPE<n>` and any class as `CLASS<n>` (decimal, 0–65535, prefix
// matched case-insensitively).
const (
	genericTypePrefix  = "TYPE"
	genericClassPrefix = "CLASS"
)

// parseGenericMnemonic parses `<prefix><decimal>` case-insensitively.
// Returns ok=false for anything else, including out-of-range values.
func parseGenericMnemonic(s, prefix string) (uint16, bool) {
	if len(s) <= len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return 0, false
	}
	n, err := strconv.ParseUint(s[len(prefix):], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// RRTypeName returns the mnemonic for t, falling back to the RFC 3597
// `TYPE<n>` form for types without one. It never fails, so it is the
// right choice wherever presentation output needs a type name.
func RRTypeName(t uint16) string {
	if s, err := RRTypeToString(t); err == nil {
		return s
	}
	return genericTypePrefix + strconv.FormatUint(uint64(t), 10)
}

// RRClassName returns the mnemonic for c, falling back to the RFC 3597
// `CLASS<n>` form for classes without one.
func RRClassName(c uint16) string {
	if s, err := RRClassToString(c); err == nil {
		return s
	}
	return genericClassPrefix + strconv.FormatUint(uint64(c), 10)
}
