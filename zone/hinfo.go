package zone

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// HINFO is the RR handler for HINFO (RFC 1035 §3.3.2).
//
// Wire format: cpu<character-string> + os<character-string>, where each
// character-string is a length octet followed by that many octets
// (RFC 1035 §3.3).
//
// Presentation format: two character-strings separated by whitespace,
// either bare tokens or quoted with backslash escapes.
type HINFO struct {
	rr *ResourceRecord

	CPU string
	OS  string
}

// ParseHINFO constructs an HINFO handler from RR presentation form.
// Returns [ErrPresentationFormat] when fewer than two character-strings
// can be extracted.
func ParseHINFO(rr *ResourceRecord, value string) (*HINFO, error) {
	tokens, err := parseCharacterStrings(value, 2)
	if err != nil {
		return nil, fmt.Errorf("%w: HINFO: %v", ErrPresentationFormat, err)
	}
	return &HINFO{
		rr:  rr,
		CPU: tokens[0],
		OS:  tokens[1],
	}, nil
}

// WireBody emits `rdlen(2) + cpu_len(1) + cpu + os_len(1) + os`.
//
// Character-strings cap at 255 octets per RFC 1035 §3.3; an over-long
// CPU or OS yields [ErrRDataFormat].
func (h *HINFO) WireBody(b *wire.Builder) error {
	cpu := []byte(h.CPU)
	os := []byte(h.OS)
	if len(cpu) > 255 {
		return fmt.Errorf("%w: HINFO CPU > 255 octets", ErrRDataFormat)
	}
	if len(os) > 255 {
		return fmt.Errorf("%w: HINFO OS > 255 octets", ErrRDataFormat)
	}
	b.AppendUint16(uint16(2 + len(cpu) + len(os)))
	b.AppendUint8(uint8(len(cpu)))
	b.AppendBytes(cpu)
	b.AppendUint8(uint8(len(os)))
	b.AppendBytes(os)
	return nil
}

// Clone returns a copy of h.
func (h *HINFO) Clone() RecordHandler {
	return &HINFO{rr: h.rr, CPU: h.CPU, OS: h.OS}
}

// hinfoFactory adapts [ParseHINFO] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func hinfoFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseHINFO(rr, value)
	if err != nil {
		return nil
	}
	return h
}

// parseCharacterStrings tokenises value into up to want quoted or bare
// strings using RFC 1035 §5.1 character-string lexing rules: a token may
// be `"..."` with backslash escapes, or a whitespace-delimited bare run.
// Returns an error if fewer than want tokens are produced.
func parseCharacterStrings(value string, want int) ([]string, error) {
	out := make([]string, 0, want)
	i, n := 0, len(value)
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	for len(out) < want && i < n {
		// Skip whitespace.
		for i < n && isSpace(value[i]) {
			i++
		}
		if i >= n {
			break
		}
		if value[i] == '"' {
			i++
			var sb strings.Builder
			for i < n && value[i] != '"' {
				if value[i] == '\\' && i+1 < n {
					i++
				}
				sb.WriteByte(value[i])
				i++
			}
			if i < n {
				i++ // closing quote
			}
			out = append(out, sb.String())
		} else {
			start := i
			for i < n && !isSpace(value[i]) {
				i++
			}
			out = append(out, value[start:i])
		}
	}
	if len(out) < want {
		return nil, fmt.Errorf("expected %d character-strings, got %d in %q", want, len(out), value)
	}
	return out, nil
}
