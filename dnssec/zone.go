package dnssec

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// KeyVerifyMode chooses what extra key-chain checks [Zone.VerifyRRSIG]
// performs on top of plain RRSIG signature verification.
type KeyVerifyMode uint8

const (
	// KeyModeNone verifies the signature only.
	KeyModeNone KeyVerifyMode = 0
	// KeyModeZSK additionally requires the signing key to be a valid
	// ZSK (signed by an in-zone KSK whose DS chain reaches a trust anchor).
	KeyModeZSK KeyVerifyMode = 0x01
	// KeyModeKSK additionally requires the signing key to be a valid
	// KSK (matched against a DS record in the parent zone or against a
	// trust anchor). Signatures on DNSKEY rrsets made by a ZSK are
	// short-circuited as valid.
	KeyModeKSK KeyVerifyMode = 0x02
	// KeyModeCSK treats the signing key as a Combined Signing Key
	// (KSK + ZSK in one). Equivalent to KeyModeKSK for SEP-flagged keys.
	KeyModeCSK KeyVerifyMode = 0x04
)

// Zone augments [zone.Zone] with the DNSSEC-aware helpers needed by the
// chain validator: RRSIG / DNSKEY / DS lookup, RFC 4034 §6.2 canonical
// digest-target construction, signature verification, and a parent
// pointer so DS records are queried in the right zone.
//
// A pointer receiver is used throughout because the embedded
// *zone.Zone is itself a pointer; constructing via `&dnssec.Zone{}`
// gives a ready-to-use, empty zone.
type Zone struct {
	*zone.Zone
	parent *Zone
	seps   []string
}

// NewZone constructs an empty DNSSEC zone.
func NewZone() *Zone {
	return &Zone{Zone: &zone.Zone{}}
}

// Parent returns the parent zone, or nil if this zone is the top of the
// configured chain (e.g. the root or an unattached trust anchor).
func (z *Zone) Parent() *Zone { return z.parent }

// SetParent attaches a parent zone. The parent is consulted when DS
// records or KSK validations are needed for child-zone lookups.
func (z *Zone) SetParent(p *Zone) { z.parent = p }

// AddSEP marks name as a Secure Entry Point (trust anchor). When the
// chain walker reaches a DNSKEY at name and the SEP set contains it,
// validation succeeds without consulting a parent DS RRset.
func (z *Zone) AddSEP(name string) {
	z.seps = append(z.seps, name)
}

// IsSecureEntryPoint reports whether name is registered as an SEP.
func (z *Zone) IsSecureEntryPoint(name string) bool {
	return slices.Contains(z.seps, name)
}

// FindRRSIGs returns all RRSIG handlers in this zone that cover the
// (name, typeCovered) RRset. If signer is non-empty it additionally
// filters by signer name.
func (z *Zone) FindRRSIGs(name string, typeCovered uint16, signer string) []*RRSig {
	candidates := z.FindRRSet(name, types.TypeRRSIG)
	var out []*RRSig
	for _, rr := range candidates {
		h, ok := rr.Handler().(*RRSig)
		if !ok {
			continue
		}
		if h.TypeCovered != typeCovered {
			continue
		}
		if signer != "" && h.Signer != signer {
			continue
		}
		out = append(out, h)
	}
	return out
}

// FindDNSKey returns the first DNSKEY at signerName whose KeyTag
// matches. Pass keyTag = 0 to accept any tag.
func (z *Zone) FindDNSKey(signerName string, keyTag uint16) *DNSKey {
	candidates := z.FindRRSet(signerName, types.TypeDNSKEY)
	for _, rr := range candidates {
		h, ok := rr.Handler().(*DNSKey)
		if !ok {
			continue
		}
		if keyTag == 0 || h.KeyTag == keyTag {
			return h
		}
	}
	return nil
}

// CreateDigestTarget builds the byte string that an RRSIG signature
// covers per RFC 4034 §6.2: the RRSIG RDATA (without the signature),
// followed by `wire_header || original_ttl || wire_body` for every
// member of the covered RRset, sorted into canonical (RDATA-binary)
// order.
//
// Returns (nil, nil) if no RRset matches (name, typeCovered) — the
// caller must treat this as a verification failure.
func (z *Zone) CreateDigestTarget(rrsig *RRSig, name string, typeCovered uint16) ([]byte, error) {
	rrset := z.FindRRSet(name, typeCovered)
	if len(rrset) == 0 {
		return nil, nil
	}

	var header wire.Builder
	if err := rrset[0].WireHeader(&header); err != nil {
		return nil, fmt.Errorf("%w: wire header: %v", ErrDNSSEC, err)
	}
	headerBytes := header.Clone()

	bodies := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		var b wire.Builder
		if err := rr.WireBody(&b); err != nil {
			return nil, fmt.Errorf("%w: wire body for %s: %v", ErrDNSSEC, rr.Label, err)
		}
		bodies = append(bodies, b.Clone())
	}
	slices.SortFunc(bodies, bytes.Compare)

	digestTarget, err := rrsig.RDataDigestTarget()
	if err != nil {
		return nil, err
	}

	var out wire.Builder
	out.AppendBytes(digestTarget)
	for _, body := range bodies {
		out.AppendBytes(headerBytes)
		out.AppendUint32(rrsig.OriginalTTL)
		out.AppendBytes(body)
	}
	return out.Clone(), nil
}

// VerifyRRSIG checks one RRSIG against the RRset it covers. Returns
// (true, nil) on success; (false, nil) when verification fails for a
// non-erroneous reason (missing key, signature mismatch); (false, err)
// when the verification could not be attempted at all.
func (z *Zone) VerifyRRSIG(name string, typeCovered uint16, rrsig *RRSig, mode KeyVerifyMode) (bool, error) {
	dnskey := z.FindDNSKey(rrsig.Signer, rrsig.KeyTag)
	if dnskey == nil {
		return false, nil
	}

	switch mode {
	case KeyModeZSK:
		if !dnskey.IsSecureEntryPoint() {
			ok, err := z.verifyZSK(dnskey)
			if err != nil || !ok {
				return ok, err
			}
		}
	case KeyModeKSK:
		if dnskey.IsSecureEntryPoint() {
			ok, err := z.verifyKSK(dnskey)
			if err != nil || !ok {
				return ok, err
			}
			if typeCovered == types.TypeDNSKEY {
				// RFC 4035 §5.3.2: signature on DNSKEY rrset by a ZSK
				// is ignored when explicitly asked for KSK-mode trust.
				return true, nil
			}
		}
	case KeyModeCSK:
		if dnskey.IsSecureEntryPoint() {
			ok, err := z.verifyKSK(dnskey)
			if err != nil || !ok {
				return ok, err
			}
		}
	}

	digestTarget, err := z.CreateDigestTarget(rrsig, name, typeCovered)
	if err != nil {
		return false, err
	}
	if digestTarget == nil {
		return false, nil
	}
	return dnskey.Verify(digestTarget, rrsig.Signature)
}

// VerifyRRSet applies RFC 4035 §5.3.3 "any-valid" semantics: the RRset
// is considered valid as soon as one RRSIG verifies.
func (z *Zone) VerifyRRSet(name string, typeCovered uint16, mode KeyVerifyMode, signer string) (bool, error) {
	sigs := z.FindRRSIGs(name, typeCovered, signer)
	if len(sigs) == 0 {
		return false, nil
	}
	var firstErr error
	for _, sig := range sigs {
		ok, err := z.VerifyRRSIG(name, typeCovered, sig, mode)
		if err != nil && firstErr == nil {
			firstErr = err
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, firstErr
}

// verifyKSK asserts that dnskey is a valid Key-Signing Key — i.e. that
// its DS digest matches a DS record in the parent zone (or it is a
// configured trust anchor).
func (z *Zone) verifyKSK(dnskey *DNSKey) (bool, error) {
	return z.verifyDelegationSigner(dnskey)
}

// verifyZSK asserts that dnskey is a valid Zone-Signing Key — i.e.
// that the DNSKEY rrset containing it is itself signed by a KSK in the
// same zone.
func (z *Zone) verifyZSK(dnskey *DNSKey) (bool, error) {
	return z.VerifyRRSet(dnskey.Label(), types.TypeDNSKEY, KeyModeKSK, "")
}

// VerifyDSRRSet verifies the DS rrset for childName using the parent's
// keys. Used when descending a chain from parent to child.
func (z *Zone) VerifyDSRRSet(childName string) (bool, error) {
	if z.parent == nil {
		return false, nil
	}
	return z.parent.VerifyRRSet(childName, types.TypeDS, KeyModeNone, "")
}

// verifyDelegationSigner reports whether dnskey is authenticated either
// as a configured SEP or by matching a DS record in the parent zone.
func (z *Zone) verifyDelegationSigner(dnskey *DNSKey) (bool, error) {
	if z.IsSecureEntryPoint(dnskey.Label()) {
		return true, nil
	}

	src := z
	if z.parent != nil {
		src = z.parent
	}
	dsSet := src.FindRRSet(dnskey.Label(), types.TypeDS)
	if len(dsSet) == 0 {
		return false, nil
	}

	for _, rr := range dsSet {
		ds, ok := rr.Handler().(*DS)
		if !ok {
			continue
		}
		// IANA digest types we support: 1 (SHA-1), 2 (SHA-256), 4 (SHA-384).
		if ds.DigestType != 1 && ds.DigestType != 2 && ds.DigestType != 4 {
			continue
		}
		ok, err := z.verifyDelegationSignerWithDS(dnskey, ds)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// verifyDelegationSignerWithDS checks one DS record against one
// candidate DNSKEY: algorithms must match and the digest of the
// canonical DNSKEY representation must equal DS.Digest.
func (z *Zone) verifyDelegationSignerWithDS(dnskey *DNSKey, ds *DS) (bool, error) {
	if dnskey.Algorithm != ds.Algorithm {
		return false, nil
	}
	keyDigest, err := dnskey.DSDigestData()
	if err != nil {
		return false, err
	}
	return ds.VerifyDigest(keyDigest)
}

// SignRR signs (name, typeCovered) with key and returns a new RRSIG
// ResourceRecord ready to be inserted into the zone. The signing key
// must already have its private key attached via [DNSKey.SetPrivateKey].
//
// Returns (nil, nil) if no RRset matches (name, typeCovered).
func (z *Zone) SignRR(name string, ttl uint32, typeCovered uint16, key *DNSKey, inception, expire int64) (*zone.ResourceRecord, error) {
	rrsig := NewRRSig(nil, name, ttl, typeCovered, inception, expire, key)
	digestTarget, err := z.CreateDigestTarget(rrsig, name, typeCovered)
	if err != nil {
		return nil, err
	}
	if digestTarget == nil {
		return nil, nil
	}
	signature, err := key.Sign(digestTarget)
	if err != nil {
		return nil, err
	}

	typeName, err := types.RRTypeToString(typeCovered)
	if err != nil {
		return nil, err
	}
	sigB64 := base64.StdEncoding.EncodeToString(signature)
	value := fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
		typeName, key.Algorithm, rrsig.Labels, ttl, expire, inception,
		key.KeyTag, key.Label(), sigB64)
	return zone.NewResourceRecord(name, ttl, "IN", "RRSIG", value)
}
