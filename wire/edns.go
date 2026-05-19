package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EDNS / RFC 6891 OPT pseudo-RR. OPT is a meta-RR used by EDNS(0) to
// signal extended DNS capabilities; it lives in the additional section
// of every modern DNS message and never appears in zone files.
//
// Wire layout (RFC 6891 §6.1.2) reuses the standard RR fields:
//
//	NAME:     0x00 (root)
//	TYPE:     41 (OPT)
//	CLASS:    requestor's UDP payload size (uint16)
//	TTL:      extended-rcode(8) + version(8) + DO(1) + Z(15)
//	RDLENGTH: length of RDATA
//	RDATA:    sequence of {option-code(2), option-length(2), option-data}
//
// Per RFC 6891 §6.1.3 OPT records MUST NOT be cached, forwarded, or
// stored; §6.1.4 limits one OPT per message.
type EDNS struct {
	// UDPPayloadSize is the requestor's announced UDP buffer size (CLASS).
	// Defaults to 4096 when [EDNS.Encode] sees a zero value, matching the
	// dnsdata-js constructor default.
	UDPPayloadSize uint16

	// ExtendedRCODE extends the 4-bit header RCODE (RFC 6891 §6.1.3).
	ExtendedRCODE uint8

	// Version is the EDNS version number (0 in EDNS0).
	Version uint8

	// DOBit signals "DNSSEC OK" (RFC 3225 §3).
	DOBit bool

	// Z holds the remaining 15 bits of the OPT TTL field. Reserved; SHOULD
	// be zero on transmission. Carried through verbatim on decode.
	Z uint16

	// Options is the parsed list of EDNS option-code / option-data pairs.
	// Order is preserved for round-trip fidelity.
	Options []EDNSOption
}

// EDNSOption is a single EDNS(0) option-code / option-data pair carried
// in the OPT RDATA (RFC 6891 §6.1.2).
type EDNSOption struct {
	Code uint16
	Data []byte
}

// Well-known EDNS option codes from the IANA "DNS EDNS0 Option Codes"
// registry. The remaining codes (NSID padding etc.) are intentionally
// not redeclared here; callers can use raw [EDNSOption.Code] values.
const (
	EDNSOptionNSID         uint16 = 3  // RFC 5001
	EDNSOptionClientSubnet uint16 = 8  // RFC 7871
	EDNSOptionCookie       uint16 = 10 // RFC 7873
	EDNSOptionPadding      uint16 = 12 // RFC 7830
	EDNSOptionChain        uint16 = 13 // RFC 7901
)

// OPTTypeCode is the IANA RR-type number for OPT (RFC 6891 §6.1.2).
// Exposed so callers parsing message wire bytes can identify OPT
// records without redeclaring the constant.
const OPTTypeCode uint16 = 41

// DefaultUDPPayloadSize is the EDNS(0) UDP buffer-size default used by
// [EDNS.Encode] when [EDNS.UDPPayloadSize] is zero. 4096 is the
// de-facto standard and matches the dnsdata-js constructor.
const DefaultUDPPayloadSize uint16 = 4096

// ErrOPT classifies malformed OPT wire input — too short, wrong type,
// or RDATA that exceeds its declared length.
var ErrOPT = errors.New("invalid OPT pseudo-RR")

// Encode appends the full OPT RR wire form (NAME .. RDATA) to b. A
// nil receiver is permitted and emits a default OPT with no options.
func (e *EDNS) Encode(b *Builder) {
	udp := uint16(DefaultUDPPayloadSize)
	var (
		rcode   uint8
		version uint8
		do      bool
		z       uint16
		opts    []EDNSOption
	)
	if e != nil {
		if e.UDPPayloadSize != 0 {
			udp = e.UDPPayloadSize
		}
		rcode = e.ExtendedRCODE
		version = e.Version
		do = e.DOBit
		z = e.Z & 0x7fff
		opts = e.Options
	}

	// NAME: root domain.
	b.AppendUint8(0)
	// TYPE: OPT.
	b.AppendUint16(OPTTypeCode)
	// CLASS: UDP payload size.
	b.AppendUint16(udp)
	// TTL: extended_rcode(8) + version(8) + DO(1) + Z(15).
	ttl := uint32(rcode)<<24 | uint32(version)<<16 | uint32(z)
	if do {
		ttl |= 0x8000
	}
	b.AppendUint32(ttl)

	// RDLENGTH + RDATA: each option is code(2) + length(2) + data.
	rdlen := 0
	for _, o := range opts {
		rdlen += 4 + len(o.Data)
	}
	b.AppendUint16(uint16(rdlen))
	for _, o := range opts {
		b.AppendUint16(o.Code)
		b.AppendUint16(uint16(len(o.Data)))
		b.AppendBytes(o.Data)
	}
}

// DecodeOPT parses an OPT pseudo-RR starting at the TYPE field of data.
// The NAME byte (which is always 0x00 for OPT) must already have been
// consumed by the caller — DecodeOPT expects the slice to begin with
// `TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA`.
//
// Returns [ErrOPT] for short inputs, a non-OPT type code, or RDATA that
// overruns its declared length.
func DecodeOPT(data []byte) (*EDNS, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("%w: short header (%d bytes)", ErrOPT, len(data))
	}
	typ := binary.BigEndian.Uint16(data[0:2])
	if typ != OPTTypeCode {
		return nil, fmt.Errorf("%w: type %d, expected %d", ErrOPT, typ, OPTTypeCode)
	}
	udp := binary.BigEndian.Uint16(data[2:4])
	ttl := binary.BigEndian.Uint32(data[4:8])
	rdlen := int(binary.BigEndian.Uint16(data[8:10]))
	if 10+rdlen > len(data) {
		return nil, fmt.Errorf("%w: RDLENGTH %d exceeds buffer", ErrOPT, rdlen)
	}

	rcode := uint8(ttl >> 24)
	version := uint8(ttl >> 16)
	do := (ttl & 0x8000) != 0
	z := uint16(ttl & 0x7fff)

	var opts []EDNSOption
	pos := 10
	end := 10 + rdlen
	for pos+4 <= end {
		code := binary.BigEndian.Uint16(data[pos : pos+2])
		optLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+optLen > end {
			return nil, fmt.Errorf("%w: option %d data overruns RDLENGTH", ErrOPT, code)
		}
		optData := append([]byte(nil), data[pos:pos+optLen]...)
		opts = append(opts, EDNSOption{Code: code, Data: optData})
		pos += optLen
	}
	if pos != end {
		return nil, fmt.Errorf("%w: trailing %d byte(s) after last option", ErrOPT, end-pos)
	}

	return &EDNS{
		UDPPayloadSize: udp,
		ExtendedRCODE:  rcode,
		Version:        version,
		DOBit:          do,
		Z:              z,
		Options:        opts,
	}, nil
}

// FindOption returns the first option matching code, or (zero-value, false)
// if no option with that code is present.
func (e *EDNS) FindOption(code uint16) (EDNSOption, bool) {
	if e == nil {
		return EDNSOption{}, false
	}
	for _, o := range e.Options {
		if o.Code == code {
			return o, true
		}
	}
	return EDNSOption{}, false
}
