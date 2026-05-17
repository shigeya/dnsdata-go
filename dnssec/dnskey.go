package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// DNSKey is the RR handler for DNSKEY (RFC 4034 §2) and CDNSKEY
// (RFC 7344 §3.2; identical wire and presentation format).
//
// Fields after construction are intended to be read-only; copy via
// [DNSKey.Clone] if mutation is needed.
type DNSKey struct {
	rr *zone.ResourceRecord

	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	KeyData   []byte
	KeyTag    uint16

	privateKey crypto.PrivateKey
}

// dnskeyValueRE matches the presentation form
// `<flags> <protocol> <algorithm> <base64 key>`. Whitespace inside the
// base64 region is permitted and stripped during parsing.
var dnskeyValueRE = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$`)

// ParseDNSKey constructs a DNSKey from RR presentation form. The parent
// [zone.ResourceRecord] is retained so the owner name is available for
// [DNSKey.DSDigestData] and [DNSKey.ISCKeyBaseFilename].
//
// Returns [ErrPresentationFormat] if the value does not parse.
func ParseDNSKey(rr *zone.ResourceRecord, value string) (*DNSKey, error) {
	m := dnskeyValueRE.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil, fmt.Errorf("%w: DNSKEY: %q", ErrPresentationFormat, value)
	}
	flags, err := strconv.ParseUint(m[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: DNSKEY flags %q: %v", ErrPresentationFormat, m[1], err)
	}
	protocol, err := strconv.ParseUint(m[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: DNSKEY protocol %q: %v", ErrPresentationFormat, m[2], err)
	}
	algorithm, err := strconv.ParseUint(m[3], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: DNSKEY algorithm %q: %v", ErrPresentationFormat, m[3], err)
	}
	keyB64 := stripWhitespace(m[4])
	keyData, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: DNSKEY key base64: %v", ErrPresentationFormat, err)
	}
	return NewDNSKey(rr, uint16(flags), uint8(protocol), uint8(algorithm), keyData), nil
}

// NewDNSKey constructs a DNSKey directly from numeric fields. KeyData
// is retained without copying; callers that intend to mutate the input
// must Clone it first.
func NewDNSKey(rr *zone.ResourceRecord, flags uint16, protocol, algorithm uint8, keyData []byte) *DNSKey {
	k := &DNSKey{
		rr:        rr,
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		KeyData:   keyData,
	}
	k.KeyTag = k.calcKeyTag()
	return k
}

// calcKeyTag implements the key-tag computation of RFC 4034 Appendix B.
// Algorithm 1 (RSAMD5) uses the special case in §B.1: the low 16 bits
// of the public-key modulus.
func (k *DNSKey) calcKeyTag() uint16 {
	if k.Algorithm == types.AlgoRSAMD5 {
		if len(k.KeyData) < 2 {
			return 0
		}
		return uint16(k.KeyData[len(k.KeyData)-2])<<8 | uint16(k.KeyData[len(k.KeyData)-1])
	}

	var sum uint32
	sum += uint32(k.Flags)
	sum += uint32(k.Protocol)<<8 | uint32(k.Algorithm)

	kd := k.KeyData
	for i := 0; i+1 < len(kd); i += 2 {
		sum += uint32(kd[i])<<8 | uint32(kd[i+1])
	}
	if len(kd)%2 == 1 {
		sum += uint32(kd[len(kd)-1]) << 8
	}
	sum += (sum >> 16) & 0xffff
	return uint16(sum & 0xffff)
}

// Label returns the owner name from the attached ResourceRecord, or the
// empty string if no record is attached.
func (k *DNSKey) Label() string {
	if k.rr == nil {
		return ""
	}
	return k.rr.Label
}

// IsZoneKey reports whether the Zone Key flag (bit 7, mask 0x0100) is
// set per RFC 4034 §2.1.1.
func (k *DNSKey) IsZoneKey() bool { return k.Flags&0x0100 != 0 }

// IsSecureEntryPoint reports whether the Secure Entry Point flag
// (bit 15, mask 0x0001) is set per RFC 4034 §2.1.1 / RFC 3757.
func (k *DNSKey) IsSecureEntryPoint() bool { return k.Flags&0x0001 != 0 }

// WireBody emits `rdlen(2) + flags(2) + protocol(1) + algorithm(1) + key_data`.
func (k *DNSKey) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(4 + len(k.KeyData)))
	b.AppendUint16(k.Flags)
	b.AppendUint8(k.Protocol)
	b.AppendUint8(k.Algorithm)
	b.AppendBytes(k.KeyData)
	return nil
}

// DSDigestData returns the input to a DS-record digest computation per
// RFC 4034 §5.1.4: `owner_name_wire || flags || protocol || algorithm ||
// key_data` (no rdlen prefix).
//
// Returns an error only if the owner name cannot be encoded to wire
// form (oversized labels, etc.).
func (k *DNSKey) DSDigestData() ([]byte, error) {
	if k.rr == nil {
		return nil, fmt.Errorf("%w: DNSKey has no parent record", ErrDNSSEC)
	}
	ownerWire, err := wire.DomainNameToWire(k.rr.Label)
	if err != nil {
		return nil, err
	}
	var b wire.Builder
	b.AppendBytes(ownerWire)
	b.AppendUint16(k.Flags)
	b.AppendUint8(k.Protocol)
	b.AppendUint8(k.Algorithm)
	b.AppendBytes(k.KeyData)
	return b.Clone(), nil
}

// PublicKey decodes the RDATA key field into the appropriate Go
// crypto.PublicKey type for the algorithm.
//
// Returned types:
//
//   - RSA family → [*rsa.PublicKey]
//   - ECDSA P-256 / P-384 → [*ecdsa.PublicKey]
//   - Ed25519 → [ed25519.PublicKey]
//
// Returns [ErrUnsupportedAlgorithm] for algorithms recognised by the
// type table but not implemented (e.g. Ed448, GOST, deprecated DSA).
func (k *DNSKey) PublicKey() (crypto.PublicKey, error) {
	switch k.Algorithm {
	case types.AlgoED25519:
		if len(k.KeyData) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 expects %d bytes, got %d", ErrInvalidKey, ed25519.PublicKeySize, len(k.KeyData))
		}
		return ed25519.PublicKey(append([]byte(nil), k.KeyData...)), nil
	case types.AlgoECDSAP256SHA256, types.AlgoECDSAP384SHA384:
		return loadECDSAPublicKey(k.KeyData, k.Algorithm)
	case types.AlgoRSASHA1, types.AlgoRSASHA1NSEC3SHA1,
		types.AlgoRSASHA256, types.AlgoRSASHA512:
		return loadRSAPublicKey(k.KeyData)
	}
	return nil, fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, k.Algorithm)
}

// SetPrivateKey attaches a private key for use with [DNSKey.Sign]. The
// key's type must match the DNSKey's algorithm:
//
//   - Ed25519 algorithm → [ed25519.PrivateKey]
//   - ECDSA algorithm → [*ecdsa.PrivateKey]
//   - RSA algorithm → [*rsa.PrivateKey]
//
// Type mismatches are reported only at [DNSKey.Sign] time.
func (k *DNSKey) SetPrivateKey(priv crypto.PrivateKey) {
	k.privateKey = priv
}

// Verify checks whether signature is a valid DNSSEC signature over data
// for this key's algorithm. Returns (true, nil) for a valid signature,
// (false, nil) for an invalid one, and (false, err) when verification
// could not be attempted (unsupported algorithm, malformed key, …).
func (k *DNSKey) Verify(data, signature []byte) (bool, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return false, err
	}
	switch k.Algorithm {
	case types.AlgoED25519:
		return ed25519.Verify(pub.(ed25519.PublicKey), data, signature), nil

	case types.AlgoECDSAP256SHA256, types.AlgoECDSAP384SHA384:
		h, err := ecdsaHash(k.Algorithm)
		if err != nil {
			return false, err
		}
		h.Write(data)
		digest := h.Sum(nil)
		r, s, err := ecdsaRawToInts(signature, k.Algorithm)
		if err != nil {
			return false, err
		}
		return ecdsa.Verify(pub.(*ecdsa.PublicKey), digest, r, s), nil

	case types.AlgoRSASHA1, types.AlgoRSASHA1NSEC3SHA1,
		types.AlgoRSASHA256, types.AlgoRSASHA512:
		hc, h, err := rsaHash(k.Algorithm)
		if err != nil {
			return false, err
		}
		h.Write(data)
		digest := h.Sum(nil)
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), hc, digest, signature); err != nil {
			return false, nil
		}
		return true, nil
	}
	return false, fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, k.Algorithm)
}

// Sign produces a DNSSEC signature over data using the attached private
// key. Caller must have called [DNSKey.SetPrivateKey] first.
//
// Signature format matches DNSSEC conventions: PKCS#1 v1.5 for RSA,
// raw `r || s` for ECDSA, native 64-byte form for Ed25519.
func (k *DNSKey) Sign(data []byte) ([]byte, error) {
	if k.privateKey == nil {
		return nil, fmt.Errorf("%w: no private key set", ErrInvalidKey)
	}

	switch k.Algorithm {
	case types.AlgoED25519:
		priv, ok := k.privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: Ed25519 expects ed25519.PrivateKey, got %T", ErrInvalidKey, k.privateKey)
		}
		return ed25519.Sign(priv, data), nil

	case types.AlgoECDSAP256SHA256, types.AlgoECDSAP384SHA384:
		priv, ok := k.privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA expects *ecdsa.PrivateKey, got %T", ErrInvalidKey, k.privateKey)
		}
		h, err := ecdsaHash(k.Algorithm)
		if err != nil {
			return nil, err
		}
		h.Write(data)
		digest := h.Sum(nil)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			return nil, err
		}
		return ecdsaIntsToRaw(r, s, k.Algorithm)

	case types.AlgoRSASHA1, types.AlgoRSASHA1NSEC3SHA1,
		types.AlgoRSASHA256, types.AlgoRSASHA512:
		priv, ok := k.privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: RSA expects *rsa.PrivateKey, got %T", ErrInvalidKey, k.privateKey)
		}
		hc, h, err := rsaHash(k.Algorithm)
		if err != nil {
			return nil, err
		}
		h.Write(data)
		digest := h.Sum(nil)
		return rsa.SignPKCS1v15(rand.Reader, priv, hc, digest)
	}
	return nil, fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, k.Algorithm)
}

// ISCKeyBaseFilename returns the BIND/ISC convention for DNSSEC key
// files: `K<label>+<algorithm:03d>+<keytag:05d>`.
//
// Example: `Kexample.net.+008+12345`. The owner name retains its
// trailing dot because BIND's tools do.
func (k *DNSKey) ISCKeyBaseFilename() string {
	label := ""
	if k.rr != nil {
		label = k.rr.Label
	}
	return fmt.Sprintf("K%s+%03d+%05d", label, k.Algorithm, k.KeyTag)
}

// Clone returns a deep copy detached from any cached private key.
// (Cloning a key with a private key set would be a footgun for tests.)
func (k *DNSKey) Clone() zone.RecordHandler {
	cp := &DNSKey{
		rr:        k.rr,
		Flags:     k.Flags,
		Protocol:  k.Protocol,
		Algorithm: k.Algorithm,
		KeyData:   append([]byte(nil), k.KeyData...),
		KeyTag:    k.KeyTag,
	}
	return cp
}

// stripWhitespace removes all ASCII whitespace from s. Used to undo the
// soft-wrapping permitted in DNSKEY/RRSIG base64 presentation form.
func stripWhitespace(s string) string {
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
