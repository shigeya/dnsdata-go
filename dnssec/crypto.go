package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"

	"github.com/shigeya/dnsdata-go/types"
)

// ecdsaCurveFor returns the elliptic curve and coordinate length (in
// bytes) for a DNSSEC ECDSA algorithm number, or [ErrUnsupportedAlgorithm].
func ecdsaCurveFor(algorithm uint8) (elliptic.Curve, int, error) {
	switch algorithm {
	case types.AlgoECDSAP256SHA256:
		return elliptic.P256(), 32, nil
	case types.AlgoECDSAP384SHA384:
		return elliptic.P384(), 48, nil
	}
	return nil, 0, fmt.Errorf("%w: not ECDSA: algorithm %d", ErrUnsupportedAlgorithm, algorithm)
}

// rsaHash maps an RSA-family DNSSEC algorithm number to a Go
// [crypto.Hash] and a freshly-initialised [hash.Hash]. Returns
// [ErrUnsupportedAlgorithm] for non-RSA algorithms.
//
// RSAMD5 (algorithm 1) is intentionally rejected: it is recognised by
// the type table but deprecated per RFC 6944 and is never an acceptable
// validator input.
func rsaHash(algorithm uint8) (crypto.Hash, hash.Hash, error) {
	switch algorithm {
	case types.AlgoRSASHA1, types.AlgoRSASHA1NSEC3SHA1:
		return crypto.SHA1, sha1.New(), nil
	case types.AlgoRSASHA256:
		return crypto.SHA256, sha256.New(), nil
	case types.AlgoRSASHA512:
		return crypto.SHA512, sha512.New(), nil
	}
	return 0, nil, fmt.Errorf("%w: not RSA: algorithm %d", ErrUnsupportedAlgorithm, algorithm)
}

// ecdsaHash returns the hash function paired with a DNSSEC ECDSA
// algorithm: SHA-256 for P-256 (alg 13), SHA-384 for P-384 (alg 14).
func ecdsaHash(algorithm uint8) (hash.Hash, error) {
	switch algorithm {
	case types.AlgoECDSAP256SHA256:
		return sha256.New(), nil
	case types.AlgoECDSAP384SHA384:
		return sha512.New384(), nil
	}
	return nil, fmt.Errorf("%w: not ECDSA: algorithm %d", ErrUnsupportedAlgorithm, algorithm)
}

// loadRSAPublicKey decodes an RFC 3110 RSA public-key encoding into a
// [*rsa.PublicKey].
//
// Format: a one-byte length prefix (or 3 bytes when the first is zero)
// gives the exponent length, followed by the big-endian exponent and
// modulus.
func loadRSAPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	if len(keyData) < 3 {
		return nil, fmt.Errorf("%w: RSA key too short (%d bytes)", ErrInvalidKey, len(keyData))
	}
	off := 0
	expLen := int(keyData[off])
	off++
	if expLen == 0 {
		if off+2 > len(keyData) {
			return nil, fmt.Errorf("%w: RSA key truncated in 3-byte exponent length", ErrInvalidKey)
		}
		expLen = int(keyData[off])<<8 | int(keyData[off+1])
		off += 2
	}
	if expLen == 0 {
		return nil, fmt.Errorf("%w: RSA exponent length is zero", ErrInvalidKey)
	}
	if off+expLen > len(keyData) {
		return nil, fmt.Errorf("%w: RSA key truncated in exponent (need %d, have %d)", ErrInvalidKey, expLen, len(keyData)-off)
	}
	exponent := new(big.Int).SetBytes(keyData[off : off+expLen])
	modulus := new(big.Int).SetBytes(keyData[off+expLen:])
	if !exponent.IsInt64() {
		return nil, fmt.Errorf("%w: RSA exponent does not fit in int64", ErrInvalidKey)
	}
	e := int(exponent.Int64())
	if e < 3 {
		return nil, fmt.Errorf("%w: RSA exponent %d is implausibly small", ErrInvalidKey, e)
	}
	return &rsa.PublicKey{N: modulus, E: e}, nil
}

// loadECDSAPublicKey decodes RFC 6605 raw `x || y` ECDSA coordinates
// into a [*ecdsa.PublicKey].
func loadECDSAPublicKey(keyData []byte, algorithm uint8) (*ecdsa.PublicKey, error) {
	curve, coordLen, err := ecdsaCurveFor(algorithm)
	if err != nil {
		return nil, err
	}
	if len(keyData) != coordLen*2 {
		return nil, fmt.Errorf("%w: ECDSA key length %d, want %d", ErrInvalidKey, len(keyData), coordLen*2)
	}
	x := new(big.Int).SetBytes(keyData[:coordLen])
	y := new(big.Int).SetBytes(keyData[coordLen:])
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ecdsaRawToInts splits a DNSSEC raw `r || s` ECDSA signature into the
// two big.Int values expected by [ecdsa.Verify]. Returns
// [ErrInvalidSignature] if the length does not match algorithm.
func ecdsaRawToInts(signature []byte, algorithm uint8) (*big.Int, *big.Int, error) {
	_, coordLen, err := ecdsaCurveFor(algorithm)
	if err != nil {
		return nil, nil, err
	}
	if len(signature) != coordLen*2 {
		return nil, nil, fmt.Errorf("%w: ECDSA signature length %d, want %d", ErrInvalidSignature, len(signature), coordLen*2)
	}
	r := new(big.Int).SetBytes(signature[:coordLen])
	s := new(big.Int).SetBytes(signature[coordLen:])
	return r, s, nil
}

// ecdsaIntsToRaw encodes (r, s) into DNSSEC raw `r || s` form, padding
// each coordinate to coordLen bytes (RFC 6605).
func ecdsaIntsToRaw(r, s *big.Int, algorithm uint8) ([]byte, error) {
	_, coordLen, err := ecdsaCurveFor(algorithm)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2*coordLen)
	rB := r.Bytes()
	sB := s.Bytes()
	if len(rB) > coordLen || len(sB) > coordLen {
		return nil, fmt.Errorf("%w: ECDSA r/s longer than coordinate length", ErrInvalidSignature)
	}
	copy(out[coordLen-len(rB):coordLen], rB)
	copy(out[2*coordLen-len(sB):], sB)
	return out, nil
}
