package wire

import (
	"bytes"
	"encoding/binary"
)

// Builder is an append-only buffer for assembling DNS wire-format data
// in big-endian byte order. The zero value is ready to use.
//
// This is the Go equivalent of dnsdata-js's WireBuilder; method names
// follow Go conventions (AppendUint16 vs append_uint16).
type Builder struct {
	buf []byte
}

// Len returns the number of bytes accumulated so far.
func (b *Builder) Len() int {
	return len(b.buf)
}

// AppendUint8 appends a single octet.
func (b *Builder) AppendUint8(v uint8) {
	b.buf = append(b.buf, v)
}

// AppendUint16 appends v in big-endian byte order.
func (b *Builder) AppendUint16(v uint16) {
	b.buf = binary.BigEndian.AppendUint16(b.buf, v)
}

// AppendUint32 appends v in big-endian byte order.
func (b *Builder) AppendUint32(v uint32) {
	b.buf = binary.BigEndian.AppendUint32(b.buf, v)
}

// AppendBytes appends a byte slice verbatim.
func (b *Builder) AppendBytes(p []byte) {
	b.buf = append(b.buf, p...)
}

// Bytes returns the accumulated wire-format buffer. The returned slice
// aliases the Builder's internal storage; callers that mutate it must
// not subsequently mutate the Builder, and vice versa. Use [Builder.Clone]
// for an independent copy.
func (b *Builder) Bytes() []byte {
	return b.buf
}

// Clone returns an independent copy of the accumulated buffer.
func (b *Builder) Clone() []byte {
	out := make([]byte, len(b.buf))
	copy(out, b.buf)
	return out
}

// CompareBytes does a lexicographic byte-wise comparison of a and b, the
// same ordering used by DNSSEC canonical form (RFC 4034 §6.3). Returns
// negative, zero, or positive in the manner of [bytes.Compare].
func CompareBytes(a, b []byte) int {
	return bytes.Compare(a, b)
}
