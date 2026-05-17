package dnssec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// NSEC is the RR handler for NSEC records (RFC 4034 §4).
//
// CoveredTypes is the parsed list of types from the bitmap, sorted in
// ascending numeric order so callers can iterate predictably and tests
// can compare slices directly. TypeBitmap holds the encoded form per
// RFC 4034 §4.1.2.
type NSEC struct {
	rr *zone.ResourceRecord

	NextDomain   string
	TypeBitmap   []byte
	CoveredTypes []uint16
}

// ParseNSEC constructs an NSEC handler from RR presentation form:
// `<next_domain> <type1> [<type2> ...]`.
//
// Unknown type mnemonics are ignored (matching dnsdata-js) so a zone
// emitted by a newer signer can still be parsed.
func ParseNSEC(rr *zone.ResourceRecord, value string) (*NSEC, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) < 1 {
		return nil, fmt.Errorf("%w: NSEC: %q", ErrPresentationFormat, value)
	}
	covered := make([]uint16, 0, len(parts)-1)
	for _, p := range parts[1:] {
		if t, err := types.StringToRRType(p); err == nil {
			covered = append(covered, t)
		}
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i] < covered[j] })
	return &NSEC{
		rr:           rr,
		NextDomain:   parts[0],
		TypeBitmap:   EncodeTypeBitmap(covered),
		CoveredTypes: covered,
	}, nil
}

// EncodeTypeBitmap encodes a list of RR-type numbers into the RFC 4034
// §4.1.2 bitmap form. Types may be supplied in any order; the encoder
// sorts and groups by the high byte (window number) internally.
func EncodeTypeBitmap(rrtypes []uint16) []byte {
	if len(rrtypes) == 0 {
		return nil
	}

	type window struct {
		num     uint8
		offsets []int
	}
	winMap := map[uint8][]int{}
	for _, t := range rrtypes {
		w := uint8(t >> 8)
		off := int(t & 0xff)
		winMap[w] = append(winMap[w], off)
	}

	windows := make([]window, 0, len(winMap))
	for w, offs := range winMap {
		windows = append(windows, window{num: w, offsets: offs})
	}
	sort.Slice(windows, func(i, j int) bool { return windows[i].num < windows[j].num })

	var b wire.Builder
	for _, w := range windows {
		maxOff := 0
		for _, off := range w.offsets {
			if off > maxOff {
				maxOff = off
			}
		}
		bmLen := maxOff/8 + 1
		bm := make([]byte, bmLen)
		for _, off := range w.offsets {
			bm[off/8] |= 0x80 >> (off % 8)
		}
		b.AppendUint8(w.num)
		b.AppendUint8(uint8(bmLen))
		b.AppendBytes(bm)
	}
	return b.Clone()
}

// DecodeTypeBitmap decodes an RFC 4034 §4.1.2 bitmap into its list of
// RR-type numbers (ascending order).
//
// Returns an error if the input is truncated or has an inconsistent
// length byte.
func DecodeTypeBitmap(bitmap []byte) ([]uint16, error) {
	var out []uint16
	pos := 0
	for pos < len(bitmap) {
		if pos+2 > len(bitmap) {
			return nil, fmt.Errorf("%w: NSEC bitmap: truncated window header at offset %d", ErrPresentationFormat, pos)
		}
		window := bitmap[pos]
		length := int(bitmap[pos+1])
		pos += 2
		if length == 0 || length > 32 {
			return nil, fmt.Errorf("%w: NSEC bitmap: invalid window length %d", ErrPresentationFormat, length)
		}
		if pos+length > len(bitmap) {
			return nil, fmt.Errorf("%w: NSEC bitmap: truncated window data", ErrPresentationFormat)
		}
		for i := 0; i < length; i++ {
			byteVal := bitmap[pos+i]
			for bit := 0; bit < 8; bit++ {
				if byteVal&(0x80>>bit) != 0 {
					out = append(out, uint16(window)<<8|uint16(i*8+bit))
				}
			}
		}
		pos += length
	}
	return out, nil
}

// CoversType reports whether the bitmap covers t. Linear scan over the
// presorted CoveredTypes slice.
func (n *NSEC) CoversType(t uint16) bool {
	for _, x := range n.CoveredTypes {
		if x == t {
			return true
		}
		if x > t {
			return false
		}
	}
	return false
}

// MatchesName reports whether qname is equal to owner in DNSSEC
// canonical name order (RFC 4034 §6.1).
//
// owner is the NSEC RR's owner name. It is passed explicitly because
// [ParseNSEC] is allowed to receive a nil [zone.ResourceRecord] and the
// handler does not otherwise retain its owner.
func (n *NSEC) MatchesName(owner, qname string) bool {
	return EqualCanonicalNames(owner, qname)
}

// CoversName reports whether qname falls strictly between owner and
// n.NextDomain in canonical order (RFC 4035 §5.4 "covers"). Equal to
// either endpoint returns false: a match is not a cover, and an NSEC
// only proves non-existence of names strictly inside its range.
//
// The "wrap" case where NextDomain <= owner in canonical order is
// recognised as the zone-trailing NSEC and accepted: qname is covered
// if it is greater than owner OR less than NextDomain.
func (n *NSEC) CoversName(owner, qname string) bool {
	if n == nil {
		return false
	}
	cmpOwner := CompareCanonicalNames(qname, owner)
	cmpNext := CompareCanonicalNames(qname, n.NextDomain)
	if cmpOwner == 0 || cmpNext == 0 {
		return false
	}
	if CompareCanonicalNames(n.NextDomain, owner) <= 0 {
		// Wrap-around NSEC at the zone end.
		return cmpOwner > 0 || cmpNext < 0
	}
	return cmpOwner > 0 && cmpNext < 0
}

// ProvesNoData reports whether n's bitmap is consistent with a NODATA
// proof for qtype: the bitmap does NOT cover qtype, AND it does NOT
// cover CNAME (because a CNAME would otherwise have produced an
// answer rather than NODATA, RFC 4035 §5.4).
//
// The caller must separately confirm that the NSEC's owner equals
// qname (a matching denial) — that is what makes the absence of qtype
// in the bitmap a statement about qname rather than about some
// neighbour.
func (n *NSEC) ProvesNoData(qtype uint16) bool {
	if n == nil {
		return false
	}
	if qtype == types.TypeCNAME {
		// "No CNAME at qname" is what ProvesNoData would assert; if
		// the caller is asking specifically about CNAME, the absence
		// of CNAME in the bitmap is the proof itself.
		return !n.CoversType(types.TypeCNAME)
	}
	return !n.CoversType(qtype) && !n.CoversType(types.TypeCNAME)
}

// ProvesNoDS reports whether n's type bitmap matches the shape of a
// "no-DS, signed delegation" NSEC at the parent: NS bit present, DS bit
// absent, and SOA bit absent. The presence of SOA would mean this is
// actually a zone apex NSEC, not a delegation point, and the absence of
// NS would mean the parent never delegated at all.
//
// Callers must additionally verify that this NSEC's owner equals the
// delegated child name (matching denial), or that its range covers the
// child name (covering denial); ProvesNoDS only inspects the bitmap.
func (n *NSEC) ProvesNoDS() bool {
	if n == nil {
		return false
	}
	hasNS := false
	hasDS := false
	hasSOA := false
	for _, t := range n.CoveredTypes {
		switch t {
		case types.TypeNS:
			hasNS = true
		case types.TypeDS:
			hasDS = true
		case types.TypeSOA:
			hasSOA = true
		}
	}
	return hasNS && !hasDS && !hasSOA
}

// WireBody emits `rdlen(2) + next_domain_wire + type_bitmap`.
func (n *NSEC) WireBody(b *wire.Builder) error {
	nextWire, err := wire.DomainNameToWire(n.NextDomain)
	if err != nil {
		return err
	}
	b.AppendUint16(uint16(len(nextWire) + len(n.TypeBitmap)))
	b.AppendBytes(nextWire)
	b.AppendBytes(n.TypeBitmap)
	return nil
}

// Clone returns a deep copy of n.
func (n *NSEC) Clone() zone.RecordHandler {
	return &NSEC{
		rr:           n.rr,
		NextDomain:   n.NextDomain,
		TypeBitmap:   append([]byte(nil), n.TypeBitmap...),
		CoveredTypes: append([]uint16(nil), n.CoveredTypes...),
	}
}
