package zone

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// Field values that draft-shigeya-dns-opkey-00 §2.1 permits in OPKEY
// RDATA. They are the TLSA field values of the same meaning (RFC 7218
// mnemonics DANE-EE, SPKI, SHA2-256, SHA2-512).
const (
	OPKEYUsageDANEEE    uint8 = 3
	OPKEYSelectorSPKI   uint8 = 1
	OPKEYMatchingSHA256 uint8 = 1
	OPKEYMatchingSHA512 uint8 = 2
)

// opkeyFixedLength is the octet count of usage + selector + matching
// type ahead of the certificate association data (RFC 6698 §2.1).
const opkeyFixedLength = 3

// opkeyMatchingByStrength lists the permitted matching types, strongest
// first (draft §6.2: SHA-512 is preferred to SHA-256).
var opkeyMatchingByStrength = []uint8{OPKEYMatchingSHA512, OPKEYMatchingSHA256}

// ErrOPKEYMatch is returned by [MatchOPKEYSPKI] for invalid arguments.
// A key that does not match is not an error.
var ErrOPKEYMatch = errors.New("zone OPKEY match")

// OPKEY is the RDATA of an OPKEY RR (draft-shigeya-dns-opkey-00 §2).
// Its wire and presentation formats are those of TLSA (RFC 6698 §2.1,
// §2.2), and it is read and written through the TLSA codec
// ([ParseTLSA], [TLSA.WireBody], [wire.RDataToString]) so the two
// cannot drift.
//
// Decoding is permissive: any valid TLSA RDATA decodes, including
// values the draft does not permit, because a reader must ignore such
// an RR rather than fail on its RRset (draft §2.1). Readers filter
// with [OPKEY.Usable]; writers build with [NewOPKEY].
//
// The type value is not allocated yet (see [types.OPKEYType]). Until it
// is, OPKEY RDATA is published as a TLSA RRset; [OPKEYFromTLSA] reads
// it back.
type OPKEY struct {
	Usage                      uint8
	Selector                   uint8
	MatchingType               uint8
	CertificateAssociationData []byte
}

// NewOPKEY builds OPKEY RDATA for publication: usage DANE-EE (3),
// selector SPKI (1), and digest as the certificate association data.
// It rejects a matching type other than SHA-256 (1) or SHA-512 (2) and
// a digest of the wrong length for it, which the draft says MUST NOT
// be published (draft §2.1). Errors wrap [ErrRDataFormat]. digest is
// copied.
func NewOPKEY(matchingType uint8, digest []byte) (OPKEY, error) {
	k := OPKEY{
		Usage:                      OPKEYUsageDANEEE,
		Selector:                   OPKEYSelectorSPKI,
		MatchingType:               matchingType,
		CertificateAssociationData: bytes.Clone(digest),
	}
	if err := k.Check(); err != nil {
		return OPKEY{}, err
	}
	return k, nil
}

// NewOPKEYForSPKI builds the OPKEY RDATA that publishes the key whose
// DER-encoded SubjectPublicKeyInfo (RFC 5280) is spkiDER, digested with
// matchingType (SHA-256 or SHA-512). Errors wrap [ErrRDataFormat].
func NewOPKEYForSPKI(matchingType uint8, spkiDER []byte) (OPKEY, error) {
	if len(spkiDER) == 0 {
		return OPKEY{}, fmt.Errorf("%w: OPKEY: empty SubjectPublicKeyInfo", ErrRDataFormat)
	}
	digest, ok := opkeyDigest(matchingType, spkiDER)
	if !ok {
		return OPKEY{}, fmt.Errorf("%w: OPKEY matching type %d (want 1 or 2)", ErrRDataFormat, matchingType)
	}
	return NewOPKEY(matchingType, digest)
}

// DecodeOPKEYRData decodes OPKEY RDATA from its octets, whatever type
// number they arrived under: a TLSA RR (the transitional form), the
// allocated OPKEY type, or RFC 3597 generic RDATA under `TYPE<n>`
// (draft §4.2). It fails only when rdata is shorter than the three
// fixed fields; values the draft does not permit decode (see
// [OPKEY.Usable]). rdata is copied.
func DecodeOPKEYRData(rdata []byte) (OPKEY, error) {
	if len(rdata) < opkeyFixedLength {
		return OPKEY{}, fmt.Errorf("%w: OPKEY RDATA length %d, want at least %d",
			ErrRDataFormat, len(rdata), opkeyFixedLength)
	}
	return OPKEY{
		Usage:                      rdata[0],
		Selector:                   rdata[1],
		MatchingType:               rdata[2],
		CertificateAssociationData: bytes.Clone(rdata[opkeyFixedLength:]),
	}, nil
}

// ParseOPKEY parses OPKEY RDATA from its presentation form, which is
// the TLSA one (`3 1 1 <hex>`, hex in either case and possibly split by
// blanks), or from the RFC 3597 generic form `\# <len> <hex>`.
// Malformed text wraps [ErrPresentationFormat].
func ParseOPKEY(value string) (OPKEY, error) {
	raw, isGeneric, err := ParseGenericRData(value)
	if err != nil {
		return OPKEY{}, err
	}
	if isGeneric {
		return DecodeOPKEYRData(raw)
	}
	t, err := ParseTLSA(nil, value)
	if err != nil {
		return OPKEY{}, fmt.Errorf("OPKEY: %w", err)
	}
	return OPKEY{
		Usage:                      t.Usage,
		Selector:                   t.Selector,
		MatchingType:               t.MatchingType,
		CertificateAssociationData: t.CertificateAssociationData,
	}, nil
}

// OPKEYFromTLSA reads the records of a TLSA RRset as OPKEY RDATA: the
// transitional form, published before the OPKEY type value is
// allocated (draft §4.1, §4.3). It reinterprets the same octets and
// does not filter; use [OPKEY.Usable] or [MatchOPKEYSPKI] for that.
//
// A record that is not of type TLSA, or whose value does not decode as
// TLSA RDATA, is an error for the call.
func OPKEYFromTLSA(rrs []*ResourceRecord) ([]OPKEY, error) {
	out := make([]OPKEY, 0, len(rrs))
	for i, rr := range rrs {
		if rr == nil || rr.Type != types.TypeTLSA {
			return nil, fmt.Errorf("%w: OPKEYFromTLSA: record %d is not TLSA", ErrRDataFormat, i)
		}
		k, err := ParseOPKEY(rr.Value)
		if err != nil {
			return nil, fmt.Errorf("OPKEYFromTLSA: record %d: %w", i, err)
		}
		out = append(out, k)
	}
	return out, nil
}

// Check reports why k is not usable under draft §2.1, or nil when it
// is: usage 3, selector 1, matching type 1 with 32 octets of data or
// matching type 2 with 64. The error wraps [ErrRDataFormat] and names
// the first field at fault.
func (k OPKEY) Check() error {
	switch {
	case k.Usage != OPKEYUsageDANEEE:
		return fmt.Errorf("%w: OPKEY usage %d (want 3)", ErrRDataFormat, k.Usage)
	case k.Selector != OPKEYSelectorSPKI:
		return fmt.Errorf("%w: OPKEY selector %d (want 1)", ErrRDataFormat, k.Selector)
	}
	want, ok := opkeyDigestLength(k.MatchingType)
	if !ok {
		return fmt.Errorf("%w: OPKEY matching type %d (want 1 or 2)", ErrRDataFormat, k.MatchingType)
	}
	if got := len(k.CertificateAssociationData); got != want {
		return fmt.Errorf("%w: OPKEY matching type %d with %d octets of data (want %d)",
			ErrRDataFormat, k.MatchingType, got, want)
	}
	return nil
}

// Usable reports whether a verifier may use k (draft §2.1). An RR that
// is not usable is ignored, in the sense of RFC 7671; an RRset with no
// usable RR is still present. [OPKEY.Check] gives the reason.
func (k OPKEY) Usable() bool { return k.Check() == nil }

// RData returns the RDATA octets of k (a new slice).
func (k OPKEY) RData() []byte {
	var b wire.Builder
	// TLSA.WireBody never fails; it emits rdlength(2) + RDATA.
	_ = k.tlsa().WireBody(&b)
	return b.Clone()[2:]
}

// String returns the presentation form of k, as TLSA presents it:
// `usage selector matching-type hex`, or the RFC 3597 generic form when
// there is no certificate association data.
func (k OPKEY) String() string {
	rdata := k.RData()
	s, err := wire.RDataToString(rdata, types.TypeTLSA, rdata, 0)
	if err != nil {
		return wire.FormatGenericRData(rdata)
	}
	return s
}

// tlsa returns k as a TLSA handler detached from any record, so the
// TLSA encoder writes OPKEY RDATA.
func (k OPKEY) tlsa() *TLSA {
	return &TLSA{
		Usage:                      k.Usage,
		Selector:                   k.Selector,
		MatchingType:               k.MatchingType,
		CertificateAssociationData: k.CertificateAssociationData,
	}
}

// MatchOPKEYSPKI reports whether the key whose DER-encoded
// SubjectPublicKeyInfo (RFC 5280) is spkiDER is listed in keys, by the
// procedure of draft §6.2:
//
//  1. records that are not [OPKEY.Usable] are discarded;
//  2. among the matching types in supported that a usable record
//     carries, the strongest is selected (SHA-512 over SHA-256);
//  3. the key matches if and only if a usable record of the selected
//     matching type carries the digest of spkiDER.
//
// So when SHA-512 is supported and present, a key listed only by its
// SHA-256 digest does not match. supported defaults to both SHA-256
// and SHA-512. No usable record of a supported matching type means no
// match, not an error. Converting a key from another representation
// (a JWK, say) to SPKI is the caller's job; a JWK Thumbprint is never
// compared with the data (draft §2.2).
//
// The records must come from an answer the caller has validated; the
// DNSSEC status is not checked here (draft §6.1).
//
// Errors wrap [ErrOPKEYMatch]: an empty spkiDER, or a value in
// supported other than 1 or 2.
func MatchOPKEYSPKI(spkiDER []byte, keys []OPKEY, supported ...uint8) (bool, error) {
	if len(spkiDER) == 0 {
		return false, fmt.Errorf("%w: empty SubjectPublicKeyInfo", ErrOPKEYMatch)
	}
	if len(supported) == 0 {
		supported = opkeyMatchingByStrength
	}
	for _, mt := range supported {
		if _, ok := opkeyDigestLength(mt); !ok {
			return false, fmt.Errorf("%w: unsupported matching type %d (want 1 or 2)", ErrOPKEYMatch, mt)
		}
	}
	selected, ok := strongestOPKEYMatching(keys, supported)
	if !ok {
		return false, nil
	}
	digest, _ := opkeyDigest(selected, spkiDER)
	for _, k := range keys {
		if k.MatchingType == selected && k.Usable() && bytes.Equal(k.CertificateAssociationData, digest) {
			return true, nil
		}
	}
	return false, nil
}

// strongestOPKEYMatching picks the strongest matching type that is in
// supported and carried by at least one usable record of keys.
func strongestOPKEYMatching(keys []OPKEY, supported []uint8) (uint8, bool) {
	for _, mt := range opkeyMatchingByStrength {
		if bytes.IndexByte(supported, mt) < 0 {
			continue
		}
		for _, k := range keys {
			if k.MatchingType == mt && k.Usable() {
				return mt, true
			}
		}
	}
	return 0, false
}

// opkeyDigestLength returns the data length for a permitted matching
// type.
func opkeyDigestLength(matchingType uint8) (int, bool) {
	switch matchingType {
	case OPKEYMatchingSHA256:
		return sha256.Size, true
	case OPKEYMatchingSHA512:
		return sha512.Size, true
	}
	return 0, false
}

// opkeyDigest digests data with a permitted matching type.
func opkeyDigest(matchingType uint8, data []byte) ([]byte, bool) {
	switch matchingType {
	case OPKEYMatchingSHA256:
		d := sha256.Sum256(data)
		return d[:], true
	case OPKEYMatchingSHA512:
		d := sha512.Sum512(data)
		return d[:], true
	}
	return nil, false
}
