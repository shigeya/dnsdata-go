package wire

import (
	"errors"
	"fmt"
)

// Errors returned by domain name codec functions.
var (
	ErrLabelTooLong = errors.New("dns label exceeds 63 octets")
	ErrNameTooLong  = errors.New("dns name exceeds 255 octets")
	ErrTruncated    = errors.New("dns name wire data truncated")
	ErrCompressed   = errors.New("dns name uses compression pointer")
)

// DomainNameToWire encodes a textual domain name into uncompressed DNS
// wire format. A trailing 0x00 octet is appended only when the input ends
// with a dot (matching RFC 1035 absolute-name convention).
//
// ASCII uppercase letters are lowercased per RFC 4034 §6.2; all other
// bytes are copied verbatim.
//
// Returns [ErrLabelTooLong] if any label exceeds 63 octets and
// [ErrNameTooLong] if the encoded form would exceed 255 octets.
func DomainNameToWire(name string) ([]byte, error) {
	out := make([]byte, 0, len(name)+1)
	l := len(name)
	for i := 0; i < l; {
		j := i
		for j < l && name[j] != '.' {
			j++
		}
		if labelLen := j - i; labelLen != 0 {
			if labelLen > 63 {
				return nil, fmt.Errorf("%w: %d octets", ErrLabelTooLong, labelLen)
			}
			out = append(out, byte(labelLen))
			for k := i; k < j; k++ {
				out = append(out, asciiToLower(name[k]))
			}
		}
		if j < l { // consumed a dot
			i = j + 1
			if i == l { // trailing dot → absolute name
				out = append(out, 0x00)
			}
		} else {
			i = j
		}
	}
	if len(out) > 255 {
		return nil, fmt.Errorf("%w: %d octets", ErrNameTooLong, len(out))
	}
	return out, nil
}

// WireToDomainName decodes an uncompressed DNS name from wire format.
// The returned string ends with a dot iff the input was terminated by a
// 0x00 octet (i.e., is an absolute name).
//
// Returns [ErrCompressed] if a compression pointer (top two bits = 11) is
// encountered and [ErrTruncated] if the buffer ends mid-label.
func WireToDomainName(wire []byte) (string, error) {
	var out []byte
	l := len(wire)
	for i := 0; i < l; {
		s := wire[i]
		switch {
		case s == 0x00:
			out = append(out, '.')
			i++
		case s&0xC0 != 0:
			return "", fmt.Errorf("%w at offset %d", ErrCompressed, i)
		default:
			if i+1+int(s) > l {
				return "", fmt.Errorf("%w: label of %d octets at offset %d", ErrTruncated, s, i)
			}
			if i != 0 {
				out = append(out, '.')
			}
			i++
			out = append(out, wire[i:i+int(s)]...)
			i += int(s)
		}
	}
	return string(out), nil
}

// asciiToLower lowercases an ASCII letter and passes other bytes
// through unchanged. Matches the canonical-form rule of RFC 4034 §6.2.
func asciiToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
