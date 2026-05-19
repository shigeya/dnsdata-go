package wire

import (
	"fmt"
	"sort"
)

// EncodeTypeBitmap encodes a list of RR-type numbers into the RFC 4034
// §4.1.2 bitmap form. Used by NSEC, NSEC3 (RFC 5155) and CSYNC (RFC 7477
// §2.1) RDATA. The encoder accepts rrtypes in any order; it sorts and
// groups by the high byte (window number) internally.
//
// Returns nil for an empty input.
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

	var b Builder
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

// ErrTypeBitmap classifies invalid RFC 4034 §4.1.2 type-bitmap inputs:
// truncated headers, missing window data, or a length octet outside the
// permitted range [1, 32].
var ErrTypeBitmap = fmt.Errorf("invalid RFC 4034 type bitmap")

// DecodeTypeBitmap decodes an RFC 4034 §4.1.2 bitmap into its list of
// RR-type numbers in ascending order. Returns [ErrTypeBitmap] when the
// input is truncated or carries an invalid window length.
func DecodeTypeBitmap(bitmap []byte) ([]uint16, error) {
	var out []uint16
	pos := 0
	for pos < len(bitmap) {
		if pos+2 > len(bitmap) {
			return nil, fmt.Errorf("%w: truncated window header at offset %d", ErrTypeBitmap, pos)
		}
		window := bitmap[pos]
		length := int(bitmap[pos+1])
		pos += 2
		if length == 0 || length > 32 {
			return nil, fmt.Errorf("%w: invalid window length %d", ErrTypeBitmap, length)
		}
		if pos+length > len(bitmap) {
			return nil, fmt.Errorf("%w: truncated window data", ErrTypeBitmap)
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
