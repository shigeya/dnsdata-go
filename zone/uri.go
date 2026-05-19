package zone

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// URI is the RR handler for URI (RFC 7553).
//
// Wire format (§4.5): priority(2) + weight(2) + target(raw octets — NOT
// length-prefixed; the target runs to the end of RDATA).
//
// Presentation format (§4.4): `priority weight "target-URI"`.
//
// Example:
//
//	_http._tcp.example.com.  IN  URI  10 1 "http://www.example.com/path"
type URI struct {
	rr *ResourceRecord

	Priority uint16
	Weight   uint16
	Target   string
}

// uriValueRE captures the three URI presentation-form fields. The target
// is quoted; embedded double-quotes are not supported by RFC 7553.
var uriValueRE = regexp.MustCompile(`^(\d+)\s+(\d+)\s+"([^"]*)"$`)

// ParseURI constructs a URI handler from RR presentation form. Returns
// [ErrPresentationFormat] for malformed input or out-of-range numeric
// fields.
func ParseURI(rr *ResourceRecord, value string) (*URI, error) {
	m := uriValueRE.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil, fmt.Errorf("%w: URI: %q", ErrPresentationFormat, value)
	}
	priority, err := strconv.ParseUint(m[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: URI priority %q: %v", ErrPresentationFormat, m[1], err)
	}
	weight, err := strconv.ParseUint(m[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: URI weight %q: %v", ErrPresentationFormat, m[2], err)
	}
	return &URI{
		rr:       rr,
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Target:   m[3],
	}, nil
}

// WireBody emits `rdlen(2) + priority(2) + weight(2) + target(raw)`.
func (u *URI) WireBody(b *wire.Builder) error {
	target := []byte(u.Target)
	b.AppendUint16(uint16(4 + len(target)))
	b.AppendUint16(u.Priority)
	b.AppendUint16(u.Weight)
	b.AppendBytes(target)
	return nil
}

// Clone returns a deep copy of u.
func (u *URI) Clone() RecordHandler {
	return &URI{
		rr:       u.rr,
		Priority: u.Priority,
		Weight:   u.Weight,
		Target:   u.Target,
	}
}

// uriFactory adapts [ParseURI] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func uriFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseURI(rr, value)
	if err != nil {
		return nil
	}
	return h
}
