package zone

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// NAPTR is the RR handler for NAPTR (RFC 3403, DDDS).
//
// Wire format (§4.1):
//
//	order(2) + preference(2) + flags<char-string> + services<char-string>
//	+ regexp<char-string> + replacement(uncompressed domain name)
//
// Each character-string is `length(1) + data` per RFC 1035 §3.3.
//
// Presentation format:
//
//	order preference "flags" "services" "regexp" replacement
//
// Used by ENUM (RFC 6116, E.164 → URI) and SIP-related DDDS apps.
type NAPTR struct {
	rr *ResourceRecord

	Order       uint16
	Preference  uint16
	Flags       string
	Services    string
	Regexp      string
	Replacement string
}

var naptrLeadingNumberRE = regexp.MustCompile(`^(\d+)\s+`)

// ParseNAPTR constructs a NAPTR handler from RR presentation form.
// Returns [ErrPresentationFormat] for invalid input — missing fields,
// non-numeric order / preference, an unquoted flags/services/regexp
// field, or an unterminated quoted string.
func ParseNAPTR(rr *ResourceRecord, value string) (*NAPTR, error) {
	trimmed := strings.TrimSpace(value)
	pos := 0

	order, consumed, err := naptrConsumeNumber(trimmed[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: NAPTR order: %v", ErrPresentationFormat, err)
	}
	pos += consumed
	if order > 0xFFFF {
		return nil, fmt.Errorf("%w: NAPTR order %d > 0xFFFF", ErrPresentationFormat, order)
	}

	pref, consumed, err := naptrConsumeNumber(trimmed[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: NAPTR preference: %v", ErrPresentationFormat, err)
	}
	pos += consumed
	if pref > 0xFFFF {
		return nil, fmt.Errorf("%w: NAPTR preference %d > 0xFFFF", ErrPresentationFormat, pref)
	}

	flags, consumed, err := naptrConsumeQuoted(trimmed[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: NAPTR flags: %v", ErrPresentationFormat, err)
	}
	pos += consumed

	services, consumed, err := naptrConsumeQuoted(trimmed[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: NAPTR services: %v", ErrPresentationFormat, err)
	}
	pos += consumed

	regexpVal, consumed, err := naptrConsumeQuoted(trimmed[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: NAPTR regexp: %v", ErrPresentationFormat, err)
	}
	pos += consumed

	rest := strings.Fields(strings.TrimSpace(trimmed[pos:]))
	if len(rest) == 0 {
		return nil, fmt.Errorf("%w: NAPTR: missing replacement in %q", ErrPresentationFormat, value)
	}

	return &NAPTR{
		rr:          rr,
		Order:       uint16(order),
		Preference:  uint16(pref),
		Flags:       flags,
		Services:    services,
		Regexp:      regexpVal,
		Replacement: rest[0],
	}, nil
}

// WireBody emits `rdlen(2) + order(2) + preference(2) + flags-cs +
// services-cs + regexp-cs + replacement-name`.
//
// Returns [ErrRDataFormat] if any character-string exceeds 255 octets or
// the replacement name fails wire encoding.
func (n *NAPTR) WireBody(b *wire.Builder) error {
	flags := []byte(n.Flags)
	services := []byte(n.Services)
	regexpB := []byte(n.Regexp)
	if len(flags) > 255 {
		return fmt.Errorf("%w: NAPTR flags > 255 octets", ErrRDataFormat)
	}
	if len(services) > 255 {
		return fmt.Errorf("%w: NAPTR services > 255 octets", ErrRDataFormat)
	}
	if len(regexpB) > 255 {
		return fmt.Errorf("%w: NAPTR regexp > 255 octets", ErrRDataFormat)
	}
	replacement, err := wire.DomainNameToWire(n.Replacement)
	if err != nil {
		return fmt.Errorf("%w: NAPTR replacement %q: %v", ErrRDataFormat, n.Replacement, err)
	}
	rdlen := 2 + 2 + 1 + len(flags) + 1 + len(services) + 1 + len(regexpB) + len(replacement)
	b.AppendUint16(uint16(rdlen))
	b.AppendUint16(n.Order)
	b.AppendUint16(n.Preference)
	b.AppendUint8(uint8(len(flags)))
	b.AppendBytes(flags)
	b.AppendUint8(uint8(len(services)))
	b.AppendBytes(services)
	b.AppendUint8(uint8(len(regexpB)))
	b.AppendBytes(regexpB)
	b.AppendBytes(replacement)
	return nil
}

// Clone returns a copy of n. All non-pointer fields are value types so
// the shallow copy is independent.
func (n *NAPTR) Clone() RecordHandler {
	cp := *n
	return &cp
}

// naptrFactory adapts [ParseNAPTR] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func naptrFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseNAPTR(rr, value)
	if err != nil {
		return nil
	}
	return h
}

// naptrConsumeNumber pulls a leading decimal integer followed by
// whitespace from s. Returns the parsed value and bytes consumed.
func naptrConsumeNumber(s string) (uint64, int, error) {
	m := naptrLeadingNumberRE.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, fmt.Errorf("expected leading decimal number in %q", s)
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return n, len(m[0]), nil
}

// naptrConsumeQuoted pulls one `"..."` token from s, honouring `\\`
// escapes, then skips trailing whitespace. Returns the unquoted value
// and bytes consumed.
func naptrConsumeQuoted(s string) (string, int, error) {
	pos := 0
	for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
		pos++
	}
	if pos >= len(s) || s[pos] != '"' {
		return "", 0, fmt.Errorf("expected quoted string at offset %d in %q", pos, s)
	}
	pos++
	var b strings.Builder
	for pos < len(s) && s[pos] != '"' {
		if s[pos] == '\\' && pos+1 < len(s) {
			pos++
		}
		b.WriteByte(s[pos])
		pos++
	}
	if pos >= len(s) {
		return "", 0, fmt.Errorf("unterminated quoted string")
	}
	pos++ // closing quote
	for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
		pos++
	}
	return b.String(), pos, nil
}
