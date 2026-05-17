package dnssec

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// DS is the RR handler for DS (RFC 4034 §5) and CDS (RFC 7344 §3.1;
// identical wire and presentation format).
//
// Digest is stored as raw bytes; the trust-anchor JSON shape that uses
// a hex string is [AnchorDS] in anchors.go.
type DS struct {
	rr *zone.ResourceRecord

	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// dsValueRE captures the four DS presentation-form fields. The digest
// region (group 4) may contain whitespace; the parser strips it before
// hex-decoding.
var dsValueRE = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$`)

// ParseDS constructs a DS handler from RR presentation form. Returns
// [ErrPresentationFormat] for malformed values.
func ParseDS(rr *zone.ResourceRecord, value string) (*DS, error) {
	m := dsValueRE.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil, fmt.Errorf("%w: DS: %q", ErrPresentationFormat, value)
	}
	keyTag, err := strconv.ParseUint(m[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: DS key-tag %q: %v", ErrPresentationFormat, m[1], err)
	}
	algorithm, err := strconv.ParseUint(m[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: DS algorithm %q: %v", ErrPresentationFormat, m[2], err)
	}
	digestType, err := strconv.ParseUint(m[3], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: DS digest-type %q: %v", ErrPresentationFormat, m[3], err)
	}
	digest, err := hex.DecodeString(stripWhitespace(m[4]))
	if err != nil {
		return nil, fmt.Errorf("%w: DS digest hex: %v", ErrPresentationFormat, err)
	}
	return &DS{
		rr:         rr,
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     digest,
	}, nil
}

// NewDS constructs a DS handler directly. Digest is retained without
// copying.
func NewDS(rr *zone.ResourceRecord, keyTag uint16, algorithm, digestType uint8, digest []byte) *DS {
	return &DS{
		rr:         rr,
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     digest,
	}
}

// WireBody emits `rdlen(2) + keyTag(2) + algorithm(1) + digestType(1) + digest`.
func (d *DS) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(4 + len(d.Digest)))
	b.AppendUint16(d.KeyTag)
	b.AppendUint8(d.Algorithm)
	b.AppendUint8(d.DigestType)
	b.AppendBytes(d.Digest)
	return nil
}

// VerifyDigest hashes keyDigestData (typically [DNSKey.DSDigestData])
// with this DS record's digest type and reports whether the result
// matches DS.Digest. Comparison is constant-time.
//
// Returns [ErrUnsupportedAlgorithm] if DigestType is not one of the
// IANA-registered values (1 = SHA-1, 2 = SHA-256, 4 = SHA-384).
func (d *DS) VerifyDigest(keyDigestData []byte) (bool, error) {
	h, err := dsHash(d.DigestType)
	if err != nil {
		return false, err
	}
	h.Write(keyDigestData)
	computed := h.Sum(nil)
	return subtle.ConstantTimeCompare(computed, d.Digest) == 1, nil
}

// Clone returns a deep copy of d.
func (d *DS) Clone() zone.RecordHandler {
	return &DS{
		rr:         d.rr,
		KeyTag:     d.KeyTag,
		Algorithm:  d.Algorithm,
		DigestType: d.DigestType,
		Digest:     append([]byte(nil), d.Digest...),
	}
}

// dsHash returns a fresh hash.Hash matching a DS DigestType, or
// [ErrUnsupportedAlgorithm] for unknown types.
//
// Registered types (IANA "DS RR Type Digest Algorithms"):
//
//   - 1: SHA-1 (RFC 3658, RFC 4509 reclassified deprecated as SHA-1 only)
//   - 2: SHA-256 (RFC 4509) — mandatory-to-implement
//   - 4: SHA-384 (RFC 6605)
//
// Type 3 (GOST 34.11-94, RFC 5933) is recognised by IANA but not
// implemented here.
func dsHash(digestType uint8) (hash.Hash, error) {
	switch digestType {
	case 1:
		return sha1.New(), nil
	case 2:
		return sha256.New(), nil
	case 4:
		return sha512.New384(), nil
	}
	return nil, fmt.Errorf("%w: DS digest type %d", ErrUnsupportedAlgorithm, digestType)
}
