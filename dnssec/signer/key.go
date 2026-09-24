// Package signer builds DNSSEC-signed zones: key generation and
// loading, DS and trust-anchor derivation, NSEC chains, and whole-zone
// signing.
//
// Everything is in memory. Nothing here reads the clock (inception and
// expiration are always supplied by the caller, so expired or
// not-yet-valid signatures can be produced on purpose), writes files,
// or keeps global state.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// DNSKEY flag values (RFC 4034 §2.1.1).
const (
	FlagZone uint16 = 0x0100
	FlagSEP  uint16 = 0x0001
	// FlagsKSK marks a key-signing key (also used for a combined
	// signing key): zone key + secure entry point, 257.
	FlagsKSK = FlagZone | FlagSEP
	// FlagsZSK marks a zone-signing key, 256.
	FlagsZSK = FlagZone
)

// dnskeyProtocol is the only valid DNSKEY protocol value (RFC 4034 §2.1.2).
const dnskeyProtocol uint8 = 3

// rsaKeyBits is the modulus size GenerateKey uses for RSA algorithms.
const rsaKeyBits = 2048

// pemTypePKCS8 is the PEM block type for a PKCS#8 private key.
const pemTypePKCS8 = "PRIVATE KEY"

var (
	// ErrSigner is the umbrella error for this package.
	ErrSigner = errors.New("dnssec signer")
	// ErrKeyFormat reports a private key that cannot be parsed or does
	// not match the declared algorithm.
	ErrKeyFormat = fmt.Errorf("%w: key format", ErrSigner)
	// ErrUnsupportedAlgorithm is shared with the dnssec package.
	ErrUnsupportedAlgorithm = dnssec.ErrUnsupportedAlgorithm
)

// Key is a DNSKEY together with its private key.
//
// The exported fields describe the public DNSKEY; the private key is
// only reachable through [Key.PKCS8PEM] and signing.
type Key struct {
	Owner     string // zone apex, fully qualified
	Flags     uint16
	Algorithm uint8
	PublicKey []byte // DNSKEY public-key field (RFC 3110 / 6605 / 8080 encoding)

	private crypto.PrivateKey
}

// GenerateKey creates a fresh key for owner. Supported algorithms: 13
// (ECDSA P-256), 14 (ECDSA P-384), 15 (Ed25519), 8 and 10 (RSA, 2048-bit
// modulus). Randomness comes from crypto/rand; for reproducible keys
// load a fixed one with [ParsePKCS8PEM] or [ParseBINDPrivate].
func GenerateKey(owner string, algorithm uint8, flags uint16) (*Key, error) {
	var priv crypto.PrivateKey
	var err error
	switch algorithm {
	case types.AlgoECDSAP256SHA256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case types.AlgoECDSAP384SHA384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case types.AlgoED25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case types.AlgoRSASHA256, types.AlgoRSASHA512:
		priv, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	default:
		return nil, fmt.Errorf("%w: generate algorithm %d", ErrUnsupportedAlgorithm, algorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: generate: %v", ErrSigner, err)
	}
	return NewKey(owner, flags, algorithm, priv)
}

// NewKey wraps an existing private key (*ecdsa.PrivateKey,
// ed25519.PrivateKey or *rsa.PrivateKey). algorithm 0 infers 13 / 14
// from the ECDSA curve, 15 for Ed25519 and 8 for RSA.
func NewKey(owner string, flags uint16, algorithm uint8, priv crypto.PrivateKey) (*Key, error) {
	if !strings.HasSuffix(owner, ".") {
		return nil, fmt.Errorf("%w: owner %q is not fully qualified", ErrSigner, owner)
	}
	if algorithm == 0 {
		algorithm = inferAlgorithm(priv)
	}
	pub, err := publicKeyField(priv, algorithm)
	if err != nil {
		return nil, err
	}
	return &Key{Owner: owner, Flags: flags, Algorithm: algorithm, PublicKey: pub, private: priv}, nil
}

func inferAlgorithm(priv crypto.PrivateKey) uint8 {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P384() {
			return types.AlgoECDSAP384SHA384
		}
		return types.AlgoECDSAP256SHA256
	case ed25519.PrivateKey:
		return types.AlgoED25519
	case *rsa.PrivateKey:
		return types.AlgoRSASHA256
	}
	return 0
}

// publicKeyField encodes the DNSKEY public-key field for priv and checks
// that priv suits algorithm.
func publicKeyField(priv crypto.PrivateKey, algorithm uint8) ([]byte, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		want := map[uint8]elliptic.Curve{
			types.AlgoECDSAP256SHA256: elliptic.P256(),
			types.AlgoECDSAP384SHA384: elliptic.P384(),
		}[algorithm]
		if want == nil || k.Curve != want {
			return nil, fmt.Errorf("%w: ECDSA key does not suit algorithm %d", ErrKeyFormat, algorithm)
		}
		raw, err := k.PublicKey.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyFormat, err)
		}
		return raw[1:], nil // RFC 6605: X || Y without the 0x04 prefix
	case ed25519.PrivateKey:
		if algorithm != types.AlgoED25519 {
			return nil, fmt.Errorf("%w: Ed25519 key does not suit algorithm %d", ErrKeyFormat, algorithm)
		}
		return append([]byte(nil), k.Public().(ed25519.PublicKey)...), nil
	case *rsa.PrivateKey:
		if algorithm != types.AlgoRSASHA256 && algorithm != types.AlgoRSASHA512 {
			return nil, fmt.Errorf("%w: RSA key does not suit algorithm %d", ErrKeyFormat, algorithm)
		}
		return rsaPublicKeyField(&k.PublicKey), nil
	}
	return nil, fmt.Errorf("%w: private key type %T", ErrUnsupportedAlgorithm, priv)
}

// rsaPublicKeyField encodes an RSA public key per RFC 3110 §2.
func rsaPublicKeyField(pub *rsa.PublicKey) []byte {
	e := big.NewInt(int64(pub.E)).Bytes()
	var out []byte
	if len(e) <= 0xFF {
		out = append(out, byte(len(e)))
	} else {
		out = append(out, 0, byte(len(e)>>8), byte(len(e)))
	}
	out = append(out, e...)
	return append(out, pub.N.Bytes()...)
}

// ParsePKCS8PEM loads a PEM-encoded PKCS#8 private key. algorithm 0
// infers it from the key (see [NewKey]).
func ParsePKCS8PEM(owner string, flags uint16, algorithm uint8, pemBytes []byte) (*Key, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != pemTypePKCS8 {
		return nil, fmt.Errorf("%w: no %q PEM block", ErrKeyFormat, pemTypePKCS8)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS#8: %v", ErrKeyFormat, err)
	}
	return NewKey(owner, flags, algorithm, priv)
}

// PKCS8PEM returns the private key as a PEM-encoded PKCS#8 block, so a
// generated key can be stored and loaded again with [ParsePKCS8PEM].
func (k *Key) PKCS8PEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.private)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS#8: %v", ErrKeyFormat, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: der}), nil
}

// IsKSK reports whether the secure-entry-point flag is set.
func (k *Key) IsKSK() bool { return k.Flags&FlagSEP != 0 }

// KeyTag returns the RFC 4034 Appendix B key tag.
func (k *Key) KeyTag() uint16 {
	return dnssec.NewDNSKey(nil, k.Flags, dnskeyProtocol, k.Algorithm, k.PublicKey).KeyTag
}

// DNSKEYValue returns the DNSKEY presentation value
// `<flags> 3 <algorithm> <base64 key>`.
func (k *Key) DNSKEYValue() string {
	return fmt.Sprintf("%d %d %d %s", k.Flags, dnskeyProtocol, k.Algorithm,
		base64.StdEncoding.EncodeToString(k.PublicKey))
}

// DNSKEYRecord returns a new DNSKEY record for the key at its owner.
func (k *Key) DNSKEYRecord(ttl uint32) (*zone.ResourceRecord, error) {
	return zone.NewResourceRecord(k.Owner, ttl, types.ClassIN, types.TypeDNSKEY, k.DNSKEYValue())
}

// signingKey returns a dnssec.DNSKey with the private key attached,
// ready for [dnssec.DNSKey.Sign].
func (k *Key) signingKey() (*dnssec.DNSKey, error) {
	rr, err := k.DNSKEYRecord(0)
	if err != nil {
		return nil, err
	}
	dk := dnssec.NewDNSKey(rr, k.Flags, dnskeyProtocol, k.Algorithm, k.PublicKey)
	dk.SetPrivateKey(k.private)
	return dk, nil
}
