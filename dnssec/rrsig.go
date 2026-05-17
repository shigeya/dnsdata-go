package dnssec

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// RRSig is the RR handler for RRSIG records (RFC 4034 §3).
//
// Inception and Expire are stored as Unix-epoch seconds (RFC 4034 §3.2
// permits either YYYYMMDDhhmmss text or a raw uint32; both are accepted
// by [ParseRRSig] and converted to int64 seconds).
type RRSig struct {
	rr *zone.ResourceRecord

	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expire      int64
	Inception   int64
	KeyTag      uint16
	Signer      string
	Signature   []byte
}

// rrsigValueRE captures the nine RRSIG presentation-form fields. The
// signature region (group 9) may include embedded whitespace; the
// parser strips it before base64-decoding.
var rrsigValueRE = regexp.MustCompile(
	`^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.+)$`,
)

// ParseRRSig constructs an RRSig from RR presentation form. Returns
// [ErrPresentationFormat] (wrapping the underlying field error) when
// any field fails to parse.
func ParseRRSig(rr *zone.ResourceRecord, value string) (*RRSig, error) {
	m := rrsigValueRE.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil, fmt.Errorf("%w: RRSIG: %q", ErrPresentationFormat, value)
	}
	typeCovered, err := types.StringToRRType(m[1])
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG type-covered %q: %v", ErrPresentationFormat, m[1], err)
	}
	algorithm, err := strconv.ParseUint(m[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG algorithm %q: %v", ErrPresentationFormat, m[2], err)
	}
	labels, err := strconv.ParseUint(m[3], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG labels %q: %v", ErrPresentationFormat, m[3], err)
	}
	originalTTL, err := strconv.ParseUint(m[4], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG original-TTL %q: %v", ErrPresentationFormat, m[4], err)
	}
	expire, err := parseDatetime(m[5])
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG expire %q: %v", ErrPresentationFormat, m[5], err)
	}
	inception, err := parseDatetime(m[6])
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG inception %q: %v", ErrPresentationFormat, m[6], err)
	}
	keyTag, err := strconv.ParseUint(m[7], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG key-tag %q: %v", ErrPresentationFormat, m[7], err)
	}
	signature, err := base64.StdEncoding.DecodeString(stripWhitespace(m[9]))
	if err != nil {
		return nil, fmt.Errorf("%w: RRSIG signature base64: %v", ErrPresentationFormat, err)
	}
	return &RRSig{
		rr:          rr,
		TypeCovered: typeCovered,
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expire:      expire,
		Inception:   inception,
		KeyTag:      keyTag2u16(keyTag),
		Signer:      m[8],
		Signature:   signature,
	}, nil
}

func keyTag2u16(v uint64) uint16 { return uint16(v) }

// NewRRSig constructs an empty RRSig prepared for signing. The
// Signature field is left zero-length; the caller is expected to fill
// it in after computing the signature against [RRSig.RDataDigestTarget]
// followed by the canonical RRset wire form (see dnssec_zone.go).
//
// Labels is derived from the count of "." in label, matching dnsdata-js
// (an "example.com." owner has 2 labels). RFC 4034 §3.1.3 treats the
// root label and a leading wildcard `*` as non-counted; tracking those
// is the caller's responsibility.
func NewRRSig(rr *zone.ResourceRecord, label string, ttl uint32, typeCovered uint16, inception, expire int64, key *DNSKey) *RRSig {
	return &RRSig{
		rr:          rr,
		TypeCovered: typeCovered,
		Algorithm:   key.Algorithm,
		Labels:      uint8(strings.Count(label, ".")),
		OriginalTTL: ttl,
		Expire:      expire,
		Inception:   inception,
		KeyTag:      key.KeyTag,
		Signer:      key.Label(),
		Signature:   nil,
	}
}

// parseDatetime accepts both the YYYYMMDDhhmmss (UTC) form preferred by
// RFC 4034 §3.2 and a bare uint32 epoch-seconds form. Returns Unix
// seconds.
func parseDatetime(s string) (int64, error) {
	if len(s) == 14 {
		t, err := time.Parse("20060102150405", s)
		if err != nil {
			return 0, err
		}
		return t.UTC().Unix(), nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int64(v), nil
}

// RDataDigestTarget returns the RDATA prefix used as the
// signed-data prefix per RFC 4034 §3.1.8.1: every field of the RRSIG
// RDATA *except* the signature, in wire order.
func (s *RRSig) RDataDigestTarget() ([]byte, error) {
	signerWire, err := wire.DomainNameToWire(s.Signer)
	if err != nil {
		return nil, err
	}
	var b wire.Builder
	b.AppendUint16(s.TypeCovered)
	b.AppendUint8(s.Algorithm)
	b.AppendUint8(s.Labels)
	b.AppendUint32(s.OriginalTTL)
	b.AppendUint32(uint32(s.Expire))
	b.AppendUint32(uint32(s.Inception))
	b.AppendUint16(s.KeyTag)
	b.AppendBytes(signerWire)
	return b.Clone(), nil
}

// WireBody emits `rdlen(2) + RDATA(no-sig) + signature`.
func (s *RRSig) WireBody(b *wire.Builder) error {
	dt, err := s.RDataDigestTarget()
	if err != nil {
		return err
	}
	b.AppendUint16(uint16(len(dt) + len(s.Signature)))
	b.AppendBytes(dt)
	b.AppendBytes(s.Signature)
	return nil
}

// ValueString returns the canonical RRSIG presentation form. Expire and
// Inception are emitted as their integer epoch-seconds, matching the
// dnsdata-js implementation.
func (s *RRSig) ValueString() string {
	typeName, err := types.RRTypeToString(s.TypeCovered)
	if err != nil {
		typeName = fmt.Sprintf("TYPE%d", s.TypeCovered)
	}
	sigB64 := base64.StdEncoding.EncodeToString(s.Signature)
	return fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
		typeName, s.Algorithm, s.Labels, s.OriginalTTL,
		s.Expire, s.Inception, s.KeyTag, s.Signer, sigB64)
}

// Clone returns a deep copy of s.
func (s *RRSig) Clone() zone.RecordHandler {
	return &RRSig{
		rr:          s.rr,
		TypeCovered: s.TypeCovered,
		Algorithm:   s.Algorithm,
		Labels:      s.Labels,
		OriginalTTL: s.OriginalTTL,
		Expire:      s.Expire,
		Inception:   s.Inception,
		KeyTag:      s.KeyTag,
		Signer:      s.Signer,
		Signature:   append([]byte(nil), s.Signature...),
	}
}
