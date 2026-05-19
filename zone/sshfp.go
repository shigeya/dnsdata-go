package zone

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// SSHFP is the RR handler for SSHFP (RFC 4255 §3.1).
//
// Wire format: algorithm(1) + fpType(1) + fingerprint(variable).
//
// Algorithm numbers (IANA "SSHFP RR Types for public key algorithms"):
//
//   - 1: RSA (RFC 4255)
//   - 2: DSA (RFC 4255)
//   - 3: ECDSA (RFC 6594)
//   - 4: Ed25519 (RFC 7479)
//   - 6: Ed448 (RFC 8709)
//
// Fingerprint types:
//
//   - 1: SHA-1 (RFC 4255)
//   - 2: SHA-256 (RFC 6594)
type SSHFP struct {
	rr *ResourceRecord

	Algorithm   uint8
	FPType      uint8
	Fingerprint []byte
}

// sshfpValueRE captures the three SSHFP presentation-form fields. The
// fingerprint region (group 3) may contain whitespace; the parser
// strips it before hex-decoding.
var sshfpValueRE = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(.+)$`)

// ParseSSHFP constructs an SSHFP handler from RR presentation form.
// Returns [ErrPresentationFormat] for malformed values.
func ParseSSHFP(rr *ResourceRecord, value string) (*SSHFP, error) {
	m := sshfpValueRE.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil, fmt.Errorf("%w: SSHFP: %q", ErrPresentationFormat, value)
	}
	algorithm, err := strconv.ParseUint(m[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: SSHFP algorithm %q: %v", ErrPresentationFormat, m[1], err)
	}
	fpType, err := strconv.ParseUint(m[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: SSHFP fp-type %q: %v", ErrPresentationFormat, m[2], err)
	}
	fp, err := hex.DecodeString(stripASCIIWhitespace(m[3]))
	if err != nil {
		return nil, fmt.Errorf("%w: SSHFP fingerprint hex: %v", ErrPresentationFormat, err)
	}
	return &SSHFP{
		rr:          rr,
		Algorithm:   uint8(algorithm),
		FPType:      uint8(fpType),
		Fingerprint: fp,
	}, nil
}

// WireBody emits `rdlen(2) + algorithm(1) + fpType(1) + fingerprint`.
func (s *SSHFP) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(2 + len(s.Fingerprint)))
	b.AppendUint8(s.Algorithm)
	b.AppendUint8(s.FPType)
	b.AppendBytes(s.Fingerprint)
	return nil
}

// Clone returns a deep copy of s.
func (s *SSHFP) Clone() RecordHandler {
	return &SSHFP{
		rr:          s.rr,
		Algorithm:   s.Algorithm,
		FPType:      s.FPType,
		Fingerprint: append([]byte(nil), s.Fingerprint...),
	}
}

// sshfpFactory adapts [ParseSSHFP] into the [HandlerFactory] signature.
// On parse failure it returns nil so the zone parser falls back to
// keeping the value as text (TS parity).
func sshfpFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseSSHFP(rr, value)
	if err != nil {
		return nil
	}
	return h
}
