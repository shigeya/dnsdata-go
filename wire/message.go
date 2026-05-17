package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrMessageMalformed is the umbrella error for [ParseMessage]
// failures. Concrete errors wrap it so callers can match with
// [errors.Is].
var ErrMessageMalformed = errors.New("dns message malformed")

// Header is the 12-byte fixed-shape DNS message header per
// RFC 1035 §4.1.1.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Standard flag-field bit positions (RFC 1035 §4.1.1, RFC 4035 §3).
// Use [Header.QR], etc., to read the corresponding bit.
const (
	flagQR uint16 = 1 << 15
	flagAA uint16 = 1 << 10
	flagTC uint16 = 1 << 9
	flagRD uint16 = 1 << 8
	flagRA uint16 = 1 << 7
	flagAD uint16 = 1 << 5
	flagCD uint16 = 1 << 4
)

// QR returns true when the message is a response (bit 0 of flags).
func (h Header) QR() bool { return h.Flags&flagQR != 0 }

// AA returns true when the response is authoritative.
func (h Header) AA() bool { return h.Flags&flagAA != 0 }

// TC returns true when the response was truncated. DoH never sets
// this; UDP responses may.
func (h Header) TC() bool { return h.Flags&flagTC != 0 }

// RD returns true when recursion was desired by the requestor.
func (h Header) RD() bool { return h.Flags&flagRD != 0 }

// RA returns true when the responder is willing to recurse.
func (h Header) RA() bool { return h.Flags&flagRA != 0 }

// AD returns true when the responder validated the data (RFC 4035 §3).
// Useful diagnostic but never used as a substitute for own-chain
// validation by this library.
func (h Header) AD() bool { return h.Flags&flagAD != 0 }

// CD returns true when checking was disabled by the requestor.
func (h Header) CD() bool { return h.Flags&flagCD != 0 }

// RCode returns the 4-bit response code (low nibble of Flags).
func (h Header) RCode() uint8 { return uint8(h.Flags & 0x000F) }

// Question is the (qname, qtype, qclass) tuple from the question
// section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RawRR is a wire-decoded resource record with its RDATA still in
// binary form. Use [RDataToString] (or a higher-level adapter) to
// produce a presentation-form value.
//
// The wire-form rdata is held as a sub-slice of the original message
// bytes; callers must not mutate it. RDataStart records the absolute
// offset of RData within the original message so callers decoding
// embedded domain names can call [ParseDomainName] with the right
// position.
type RawRR struct {
	Name       string
	Type       uint16
	Class      uint16
	TTL        uint32
	RData      []byte
	RDataStart int
}

// RawMessage is a wire-decoded DNS message, with each section
// returned as []RawRR. The original message bytes are retained so
// callers can decompress names referenced from rdata.
type RawMessage struct {
	Raw        []byte
	Header     Header
	Question   Question
	Answer     []RawRR
	Authority  []RawRR
	Additional []RawRR
}

// ParseMessage decodes a DNS message from msg. The returned
// [RawMessage] aliases msg; callers must not mutate the source slice
// until they are done with the result.
//
// Only one question is accepted (matching real-world DNS practice);
// QDCount > 1 returns [ErrMessageMalformed].
func ParseMessage(msg []byte) (*RawMessage, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("%w: header truncated (len=%d)", ErrMessageMalformed, len(msg))
	}
	hdr := Header{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}
	if hdr.QDCount != 1 {
		return nil, fmt.Errorf("%w: QDCount=%d (only 1 supported)", ErrMessageMalformed, hdr.QDCount)
	}

	pos := 12
	qname, next, err := ParseDomainName(msg, pos)
	if err != nil {
		return nil, fmt.Errorf("%w: question qname: %v", ErrMessageMalformed, err)
	}
	pos = next
	if pos+4 > len(msg) {
		return nil, fmt.Errorf("%w: question fields truncated", ErrMessageMalformed)
	}
	q := Question{
		Name:  qname,
		Type:  binary.BigEndian.Uint16(msg[pos : pos+2]),
		Class: binary.BigEndian.Uint16(msg[pos+2 : pos+4]),
	}
	pos += 4

	answer, pos, err := parseRRSection(msg, pos, int(hdr.ANCount))
	if err != nil {
		return nil, fmt.Errorf("%w: answer section: %v", ErrMessageMalformed, err)
	}
	authority, pos, err := parseRRSection(msg, pos, int(hdr.NSCount))
	if err != nil {
		return nil, fmt.Errorf("%w: authority section: %v", ErrMessageMalformed, err)
	}
	additional, _, err := parseRRSection(msg, pos, int(hdr.ARCount))
	if err != nil {
		return nil, fmt.Errorf("%w: additional section: %v", ErrMessageMalformed, err)
	}

	return &RawMessage{
		Raw:        msg,
		Header:     hdr,
		Question:   q,
		Answer:     answer,
		Authority:  authority,
		Additional: additional,
	}, nil
}

// parseRRSection reads count resource records starting at pos.
// Returns the parsed slice, the offset just after the section, and
// any error encountered.
func parseRRSection(msg []byte, pos, count int) ([]RawRR, int, error) {
	if count == 0 {
		return nil, pos, nil
	}
	out := make([]RawRR, 0, count)
	for i := 0; i < count; i++ {
		rr, next, err := parseRR(msg, pos)
		if err != nil {
			return nil, 0, fmt.Errorf("RR %d: %w", i, err)
		}
		out = append(out, rr)
		pos = next
	}
	return out, pos, nil
}

// parseRR reads a single RR at offset pos: owner name (possibly
// compressed) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata.
func parseRR(msg []byte, pos int) (RawRR, int, error) {
	name, next, err := ParseDomainName(msg, pos)
	if err != nil {
		return RawRR{}, 0, fmt.Errorf("owner name: %w", err)
	}
	pos = next
	if pos+10 > len(msg) {
		return RawRR{}, 0, fmt.Errorf("%w: RR fixed fields truncated at %d", ErrMessageMalformed, pos)
	}
	rrtype := binary.BigEndian.Uint16(msg[pos : pos+2])
	rrclass := binary.BigEndian.Uint16(msg[pos+2 : pos+4])
	ttl := binary.BigEndian.Uint32(msg[pos+4 : pos+8])
	rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
	pos += 10
	if pos+rdlen > len(msg) {
		return RawRR{}, 0, fmt.Errorf("%w: rdata truncated (need %d, have %d)", ErrMessageMalformed, rdlen, len(msg)-pos)
	}
	rdataStart := pos
	rdata := msg[pos : pos+rdlen]
	pos += rdlen
	return RawRR{
		Name:       name,
		Type:       rrtype,
		Class:      rrclass,
		TTL:        ttl,
		RData:      rdata,
		RDataStart: rdataStart,
	}, pos, nil
}
