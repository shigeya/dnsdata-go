package signer

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/wire"
)

// DS digest types this package produces (RFC 4509, RFC 6605). SHA-1
// (type 1) is deliberately not offered.
const (
	DigestSHA256 uint8 = 2
	DigestSHA384 uint8 = 4
)

// anchorsSource names the producer in [dnssec.RootAnchors.Source].
const anchorsSource = "dnsdata-go/dnssec/signer"

// dsDigest computes the RFC 4034 §5.1.4 digest of the key's DNSKEY:
// H(owner || flags || protocol || algorithm || public key).
func (k *Key) dsDigest(digestType uint8) ([]byte, error) {
	owner, err := wire.DomainNameToWire(k.Owner)
	if err != nil {
		return nil, fmt.Errorf("%w: owner %q: %v", ErrSigner, k.Owner, err)
	}
	input := append(owner, byte(k.Flags>>8), byte(k.Flags), dnskeyProtocol, k.Algorithm)
	input = append(input, k.PublicKey...)
	switch digestType {
	case DigestSHA256:
		sum := sha256.Sum256(input)
		return sum[:], nil
	case DigestSHA384:
		sum := sha512.Sum384(input)
		return sum[:], nil
	}
	return nil, fmt.Errorf("%w: DS digest type %d", ErrUnsupportedAlgorithm, digestType)
}

// DS returns the DS presentation value for the key, `<key tag>
// <algorithm> <digest type> <hex digest>`, for digest type 2 (SHA-256)
// or 4 (SHA-384). Place it at the key's owner in the parent zone.
func (k *Key) DS(digestType uint8) (string, error) {
	digest, err := k.dsDigest(digestType)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %d %d %s", k.KeyTag(), k.Algorithm, digestType, hex.EncodeToString(digest)), nil
}

// AnchorDS returns the key's DS in the trust-anchor form the verifier
// takes ([dnssec.AnchorDS], digest in upper-case hex).
func (k *Key) AnchorDS(digestType uint8) (dnssec.AnchorDS, error) {
	digest, err := k.dsDigest(digestType)
	if err != nil {
		return dnssec.AnchorDS{}, err
	}
	return dnssec.AnchorDS{
		KeyTag:     k.KeyTag(),
		Algorithm:  k.Algorithm,
		DigestType: digestType,
		Digest:     strings.ToUpper(hex.EncodeToString(digest)),
	}, nil
}

// RootAnchors builds trust anchors for a self-made root: one SHA-256 DS
// per KSK among keys. Pass the result to verifier.WithTrustAnchors to
// validate a hierarchy signed under that root. Every key must be owned
// by "."; ZSKs are skipped.
func RootAnchors(keys ...*Key) (*dnssec.RootAnchors, error) {
	anchors := &dnssec.RootAnchors{Source: anchorsSource}
	for _, k := range keys {
		if k.Owner != "." {
			return nil, fmt.Errorf("%w: RootAnchors: key owner %q is not the root", ErrSigner, k.Owner)
		}
		if !k.IsKSK() {
			continue
		}
		ds, err := k.AnchorDS(DigestSHA256)
		if err != nil {
			return nil, err
		}
		anchors.DS = append(anchors.DS, ds)
	}
	if len(anchors.DS) == 0 {
		return nil, fmt.Errorf("%w: RootAnchors: no KSK among the keys", ErrSigner)
	}
	return anchors, nil
}
