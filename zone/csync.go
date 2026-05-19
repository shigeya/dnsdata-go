package zone

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// CSYNC is the RR handler for CSYNC / Child-to-Parent Synchronization
// (RFC 7477).
//
// Wire format (§2.1):
//
//	SOA_Serial(4) + Flags(2) + Type_Bit_Map(variable)
//
// Flags (§3):
//
//   - 0x0001 "immediate": process the record without waiting for parent
//     verification.
//   - 0x0002 "soaminimum": activate SOA-serial validation against the
//     child's SOA.
//
// Type Bit Map uses the RFC 4034 §4.1.2 encoding (shared with NSEC and
// NSEC3); we reuse [wire.EncodeTypeBitmap].
//
// Presentation format: `soa_serial flags type1 type2 ...` — e.g.
// `66 3 A NS AAAA`. Unknown type mnemonics are silently dropped to mirror
// the TS handler.
type CSYNC struct {
	rr *ResourceRecord

	SOASerial    uint32
	Flags        uint16
	CoveredTypes []uint16
	TypeBitmap   []byte
}

// ParseCSYNC constructs a CSYNC handler from RR presentation form.
// Returns [ErrPresentationFormat] when fewer than two leading numeric
// fields are present or either header value fails to decode.
func ParseCSYNC(rr *ResourceRecord, value string) (*CSYNC, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: CSYNC: %q", ErrPresentationFormat, value)
	}
	serial, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: CSYNC soa_serial %q: %v", ErrPresentationFormat, parts[0], err)
	}
	flags, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: CSYNC flags %q: %v", ErrPresentationFormat, parts[1], err)
	}
	covered := make([]uint16, 0, len(parts)-2)
	for _, p := range parts[2:] {
		// Unknown mnemonics are dropped (TS parity): a zone signed by a
		// newer tool with as-yet-unhandled RR types is still parseable.
		if t, err := types.StringToRRType(p); err == nil {
			covered = append(covered, t)
		}
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i] < covered[j] })
	return &CSYNC{
		rr:           rr,
		SOASerial:    uint32(serial),
		Flags:        uint16(flags),
		CoveredTypes: covered,
		TypeBitmap:   wire.EncodeTypeBitmap(covered),
	}, nil
}

// WireBody emits `rdlen(2) + soa_serial(4) + flags(2) + type_bitmap`.
func (c *CSYNC) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(6 + len(c.TypeBitmap)))
	b.AppendUint32(c.SOASerial)
	b.AppendUint16(c.Flags)
	b.AppendBytes(c.TypeBitmap)
	return nil
}

// Clone returns a deep copy of c.
func (c *CSYNC) Clone() RecordHandler {
	return &CSYNC{
		rr:           c.rr,
		SOASerial:    c.SOASerial,
		Flags:        c.Flags,
		CoveredTypes: append([]uint16(nil), c.CoveredTypes...),
		TypeBitmap:   append([]byte(nil), c.TypeBitmap...),
	}
}

// csyncFactory adapts [ParseCSYNC] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func csyncFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseCSYNC(rr, value)
	if err != nil {
		return nil
	}
	return h
}
