package zone

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// TLSA is the RR handler for TLSA (RFC 6698 §2.1) and SMIMEA
// (RFC 8162 §2; identical wire and presentation format).
//
// Both type codes share one struct; [smimeaFactory] forwards to
// [tlsaFactory] so SMIMEA records are decoded by the same parser.
type TLSA struct {
	rr *ResourceRecord

	Usage                       uint8
	Selector                    uint8
	MatchingType                uint8
	CertificateAssociationData  []byte
}

// tlsaValueRE captures the four TLSA / SMIMEA presentation-form fields.
// The certificate-association-data region (group 4) may contain
// whitespace; the parser strips it before hex-decoding.
var tlsaValueRE = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$`)

// ParseTLSA constructs a TLSA handler from RR presentation form.
// Returns [ErrPresentationFormat] for malformed values.
func ParseTLSA(rr *ResourceRecord, value string) (*TLSA, error) {
	m := tlsaValueRE.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil, fmt.Errorf("%w: TLSA: %q", ErrPresentationFormat, value)
	}
	usage, err := strconv.ParseUint(m[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: TLSA usage %q: %v", ErrPresentationFormat, m[1], err)
	}
	selector, err := strconv.ParseUint(m[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: TLSA selector %q: %v", ErrPresentationFormat, m[2], err)
	}
	matchingType, err := strconv.ParseUint(m[3], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: TLSA matching-type %q: %v", ErrPresentationFormat, m[3], err)
	}
	data, err := hex.DecodeString(stripASCIIWhitespace(m[4]))
	if err != nil {
		return nil, fmt.Errorf("%w: TLSA cert-association-data hex: %v", ErrPresentationFormat, err)
	}
	return &TLSA{
		rr:                         rr,
		Usage:                      uint8(usage),
		Selector:                   uint8(selector),
		MatchingType:               uint8(matchingType),
		CertificateAssociationData: data,
	}, nil
}

// WireBody emits `rdlen(2) + usage(1) + selector(1) + matchingType(1) +
// certificate_association_data`.
func (t *TLSA) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(3 + len(t.CertificateAssociationData)))
	b.AppendUint8(t.Usage)
	b.AppendUint8(t.Selector)
	b.AppendUint8(t.MatchingType)
	b.AppendBytes(t.CertificateAssociationData)
	return nil
}

// Clone returns a deep copy of t.
func (t *TLSA) Clone() RecordHandler {
	return &TLSA{
		rr:                         t.rr,
		Usage:                      t.Usage,
		Selector:                   t.Selector,
		MatchingType:               t.MatchingType,
		CertificateAssociationData: append([]byte(nil), t.CertificateAssociationData...),
	}
}

// tlsaFactory adapts [ParseTLSA] into the [HandlerFactory] signature.
// On parse failure it returns nil so the zone parser falls back to
// keeping the value as text (TS parity).
func tlsaFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseTLSA(rr, value)
	if err != nil {
		return nil
	}
	return h
}

// smimeaFactory reuses [tlsaFactory] since SMIMEA (RFC 8162) shares
// the TLSA wire and presentation format byte-for-byte.
func smimeaFactory(rr *ResourceRecord, value string) RecordHandler {
	return tlsaFactory(rr, value)
}

// stripASCIIWhitespace removes spaces, tabs, CR, and LF from s. Used
// to undo the soft-wrapping commonly present in long hex / base64
// presentation values.
func stripASCIIWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
