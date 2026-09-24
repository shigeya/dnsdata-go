package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
)

// ParseBINDPrivate loads a private key in the ISC / BIND `K*.private`
// format (`Private-key-format: v1.x`, `Algorithm: 13 (ECDSAP256SHA256)`,
// `PrivateKey: <base64>`, …) — the Go counterpart of dnsdata-js's
// dnssec_key_loader. The file carries no flags, so the caller supplies
// them. Supported algorithms: 13, 14 (`PrivateKey` = scalar), 15
// (`PrivateKey` = seed), 8 and 10 (`Modulus`, `PublicExponent`,
// `PrivateExponent`, `Prime1`, `Prime2`).
func ParseBINDPrivate(owner string, flags uint16, text []byte) (*Key, error) {
	fields := parseBINDFields(string(text))
	algorithm, err := bindAlgorithm(fields["Algorithm"])
	if err != nil {
		return nil, err
	}
	var priv crypto.PrivateKey
	switch algorithm {
	case types.AlgoECDSAP256SHA256:
		priv, err = bindECDSA(fields, elliptic.P256())
	case types.AlgoECDSAP384SHA384:
		priv, err = bindECDSA(fields, elliptic.P384())
	case types.AlgoED25519:
		priv, err = bindEd25519(fields)
	case types.AlgoRSASHA256, types.AlgoRSASHA512:
		priv, err = bindRSA(fields)
	default:
		return nil, fmt.Errorf("%w: BIND key algorithm %d", ErrUnsupportedAlgorithm, algorithm)
	}
	if err != nil {
		return nil, err
	}
	return NewKey(owner, flags, algorithm, priv)
}

// parseBINDFields reads `Name: value` lines.
func parseBINDFields(text string) map[string]string {
	fields := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && !strings.ContainsAny(name, " \t") {
			fields[name] = strings.TrimSpace(value)
		}
	}
	return fields
}

// bindAlgorithm reads the leading number of `13 (ECDSAP256SHA256)`.
func bindAlgorithm(value string) (uint8, error) {
	num, _, _ := strings.Cut(value, " ")
	n, err := strconv.ParseUint(num, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%w: Algorithm field %q", ErrKeyFormat, value)
	}
	return uint8(n), nil
}

func bindField(fields map[string]string, name string) ([]byte, error) {
	value, ok := fields[name]
	if !ok {
		return nil, fmt.Errorf("%w: missing %s", ErrKeyFormat, name)
	}
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKeyFormat, name, err)
	}
	return b, nil
}

func bindECDSA(fields map[string]string, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	d, err := bindField(fields, "PrivateKey")
	if err != nil {
		return nil, err
	}
	priv, err := ecdsa.ParseRawPrivateKey(curve, d)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDSA PrivateKey: %v", ErrKeyFormat, err)
	}
	return priv, nil
}

func bindEd25519(fields map[string]string) (ed25519.PrivateKey, error) {
	seed, err := bindField(fields, "PrivateKey")
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: Ed25519 PrivateKey is %d octets, want %d", ErrKeyFormat, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func bindRSA(fields map[string]string) (*rsa.PrivateKey, error) {
	names := []string{"Modulus", "PublicExponent", "PrivateExponent", "Prime1", "Prime2"}
	ints := make([]*big.Int, len(names))
	for i, name := range names {
		b, err := bindField(fields, name)
		if err != nil {
			return nil, err
		}
		ints[i] = new(big.Int).SetBytes(b)
	}
	if !ints[1].IsInt64() {
		return nil, fmt.Errorf("%w: RSA PublicExponent too large", ErrKeyFormat)
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: ints[0], E: int(ints[1].Int64())},
		D:         ints[2],
		Primes:    []*big.Int{ints[3], ints[4]},
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("%w: RSA key: %v", ErrKeyFormat, err)
	}
	priv.Precompute()
	return priv, nil
}
