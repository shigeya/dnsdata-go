// Package stream is the framing of DNS messages on a byte stream: a
// two-octet length in front of each message (RFC 1035 §4.2.2), for
// TCP (RFC 7766 §8) and for TLS (RFC 7858 §3.3). resolver/auth and
// resolver/dot share it.
package stream

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	prefixLength     = 2
	maxMessageLength = 0xFFFF
)

// Exchange writes query behind its length prefix in a single write
// (RFC 7766 §8) and reads one length-prefixed message back. Errors name
// the step that failed; callers wrap them with their own sentinel.
func Exchange(rw io.ReadWriter, query []byte) ([]byte, error) {
	if len(query) > maxMessageLength {
		return nil, fmt.Errorf("query of %d octets exceeds %d", len(query), maxMessageLength)
	}
	out := binary.BigEndian.AppendUint16(make([]byte, 0, prefixLength+len(query)), uint16(len(query)))
	if _, err := rw.Write(append(out, query...)); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	hdr := make([]byte, prefixLength)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr))
	if _, err := io.ReadFull(rw, resp); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return resp, nil
}
