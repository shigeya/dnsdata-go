package zone

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// CERT is the RR handler for CERT (RFC 4398 §2).
//
// Wire format: type(2) + key_tag(2) + algorithm(1) + certificate(variable).
//
// Certificate-type values (RFC 4398 §2.1): 1=PKIX, 2=SPKI, 3=PGP, 4=IPKIX,
// 5=ISPKI, 6=IPGP, 7=ACPKIX, 8=IACPKIX, 253=URI, 254=OID.
//
// Algorithm field shares the DNSKEY/RRSIG algorithm registry.
//
// Presentation format (§2.2):
//
//	type(decimal or mnemonic) key_tag algorithm certificate(base64)
type CERT struct {
	rr *ResourceRecord

	CertType    uint16
	KeyTag      uint16
	Algorithm   uint8
	Certificate []byte
}

// certTypeMnemonics is the bidirectional map from RFC 4398 §2.1.
var certTypeMnemonics = map[string]uint16{
	"PKIX":    1,
	"SPKI":    2,
	"PGP":     3,
	"IPKIX":   4,
	"ISPKI":   5,
	"IPGP":    6,
	"ACPKIX":  7,
	"IACPKIX": 8,
	"URI":     253,
	"OID":     254,
}

// parseCertType accepts either a mnemonic ("PKIX") or a decimal code.
func parseCertType(s string) (uint16, error) {
	if v, ok := certTypeMnemonics[s]; ok {
		return v, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: CERT type %q", ErrPresentationFormat, s)
	}
	return uint16(n), nil
}

// ParseCERT constructs a CERT handler from RR presentation form. Returns
// [ErrPresentationFormat] when the value lacks the four required fields or
// any field fails to decode.
func ParseCERT(rr *ResourceRecord, value string) (*CERT, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) < 4 {
		return nil, fmt.Errorf("%w: CERT: %q", ErrPresentationFormat, value)
	}
	certType, err := parseCertType(parts[0])
	if err != nil {
		return nil, err
	}
	keyTag, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: CERT key-tag %q: %v", ErrPresentationFormat, parts[1], err)
	}
	algorithm, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: CERT algorithm %q: %v", ErrPresentationFormat, parts[2], err)
	}
	// Remaining tokens are base64 fragments (possibly split for readability).
	b64 := strings.Join(parts[3:], "")
	cert, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: CERT certificate base64: %v", ErrPresentationFormat, err)
	}
	return &CERT{
		rr:          rr,
		CertType:    certType,
		KeyTag:      uint16(keyTag),
		Algorithm:   uint8(algorithm),
		Certificate: cert,
	}, nil
}

// WireBody emits `rdlen(2) + type(2) + key_tag(2) + algorithm(1) + cert`.
func (c *CERT) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(5 + len(c.Certificate)))
	b.AppendUint16(c.CertType)
	b.AppendUint16(c.KeyTag)
	b.AppendUint8(c.Algorithm)
	b.AppendBytes(c.Certificate)
	return nil
}

// Clone returns a deep copy of c.
func (c *CERT) Clone() RecordHandler {
	return &CERT{
		rr:          c.rr,
		CertType:    c.CertType,
		KeyTag:      c.KeyTag,
		Algorithm:   c.Algorithm,
		Certificate: append([]byte(nil), c.Certificate...),
	}
}

// certFactory adapts [ParseCERT] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func certFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseCERT(rr, value)
	if err != nil {
		return nil
	}
	return h
}
