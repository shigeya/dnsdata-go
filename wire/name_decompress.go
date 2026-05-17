package wire

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPointerLoop is returned when ParseDomainName detects a
// compression pointer that re-visits a previously-followed offset.
var ErrPointerLoop = errors.New("dns name compression pointer loop")

// ErrPointerForward is returned when ParseDomainName encounters a
// compression pointer that points at or past its own position.
// RFC 1035 §4.1.4 requires pointers to point earlier in the message.
var ErrPointerForward = errors.New("dns name compression pointer points forward")

// maxPointerHops caps the number of pointer indirections allowed in a
// single name decode. The total uncompressed name length is also
// bounded by 255 octets, so any well-formed message hits that limit
// long before this cap; it exists to abort obviously-malicious input.
const maxPointerHops = 32

// ParseDomainName decodes a possibly-compressed DNS name from msg
// starting at offset. It returns the decoded name (terminated by a
// trailing ".") and the offset of the first byte immediately after
// the name *as it appears at offset* — i.e. compression pointers do
// not advance the cursor past the pointer target, only past the
// pointer bytes themselves.
//
// Errors classify the malformed input: [ErrCompressed] is not used
// (this function follows pointers rather than rejecting them), but
// [ErrTruncated], [ErrPointerLoop], and [ErrPointerForward] all
// surface specific corruption modes.
func ParseDomainName(msg []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(msg) {
		return "", 0, fmt.Errorf("%w: offset %d out of bounds (len=%d)", ErrTruncated, offset, len(msg))
	}

	var labels [][]byte
	pos := offset
	next := -1
	visited := make(map[int]bool, 4)
	hops := 0

	for {
		if pos >= len(msg) {
			return "", 0, fmt.Errorf("%w: at offset %d", ErrTruncated, pos)
		}
		b := msg[pos]
		switch {
		case b == 0:
			pos++
			if next < 0 {
				next = pos
			}
			return assembleName(labels), next, nil

		case b&0xC0 == 0xC0:
			if pos+1 >= len(msg) {
				return "", 0, fmt.Errorf("%w: pointer at offset %d", ErrTruncated, pos)
			}
			ptr := int(b&0x3F)<<8 | int(msg[pos+1])
			if ptr >= pos {
				return "", 0, fmt.Errorf("%w: pointer 0x%04x at offset %d", ErrPointerForward, ptr, pos)
			}
			if next < 0 {
				next = pos + 2
			}
			if visited[ptr] {
				return "", 0, fmt.Errorf("%w: revisit 0x%04x", ErrPointerLoop, ptr)
			}
			visited[ptr] = true
			hops++
			if hops > maxPointerHops {
				return "", 0, fmt.Errorf("%w: too many pointer hops", ErrPointerLoop)
			}
			pos = ptr

		case b&0xC0 != 0:
			// 0x40 / 0x80 prefixes are reserved (extended label types,
			// not used in practice). Reject defensively.
			return "", 0, fmt.Errorf("%w: invalid label length byte 0x%02x at %d", ErrTruncated, b, pos)

		default:
			length := int(b)
			if length > 63 {
				return "", 0, fmt.Errorf("%w: label length %d at %d", ErrLabelTooLong, length, pos)
			}
			pos++
			if pos+length > len(msg) {
				return "", 0, fmt.Errorf("%w: label of %d octets at offset %d", ErrTruncated, length, pos)
			}
			labels = append(labels, msg[pos:pos+length])
			pos += length
		}
	}
}

// assembleName concatenates label bytes into a dotted, absolute name.
// The empty label list corresponds to the root ".".
func assembleName(labels [][]byte) string {
	if len(labels) == 0 {
		return "."
	}
	totalLen := len(labels) // dots
	for _, l := range labels {
		totalLen += len(l)
	}
	var b strings.Builder
	b.Grow(totalLen)
	for _, l := range labels {
		b.Write(l)
		b.WriteByte('.')
	}
	return b.String()
}
