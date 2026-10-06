package dnssec

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

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
	// ZSK: a member of the DNSKEY rrset at the signer name, which must
	// itself verify in KeyModeKSK.
	KeyModeZSK KeyVerifyMode = 0x01
	// KeyModeKSK additionally requires the signing key to be an
	// authenticated KSK: one added with [Zone.AddTrustedKey], or whose
	// DS digest matches a DS record at its owner name in the parent zone
	// ([Zone.SetParent]). The signature is always checked as well. The
	// SEP flag of the key is not consulted (RFC 4034 §2.1.1: it is a
	// hint only).
	KeyModeKSK KeyVerifyMode = 0x02
	// KeyModeCSK accepts a signing key that is valid in either
	// KeyModeKSK or KeyModeZSK (a Combined Signing Key is both).
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
//
// Record handlers (DNSKEY, RRSIG, DS, …) are resolved through the zone's
// [zone.Registry] ([Zone.SetRegistry]; the default registry when none is
// set), both for lookups and for the RDATA encoding of digest targets.
type Zone struct {
	*zone.Zone
	parent   *Zone
	seps     []string
	trusted  []*DNSKey
	now      func() time.Time
	registry *zone.Registry
}

// SetRegistry makes the zone resolve record handlers through reg. A nil
// reg means [zone.DefaultRegistry]. Fill reg with [RegisterHandlersInto]
// (and [zone.RegisterHandlersInto] for the zone types).
func (z *Zone) SetRegistry(reg *zone.Registry) { z.registry = reg }

// Registry returns the registry the zone resolves handlers through.
func (z *Zone) Registry() *zone.Registry {
	if z.registry == nil {
		return zone.DefaultRegistry()
	}
	return z.registry
}

// Handler returns rr's handler from the zone's registry
// ([zone.ResourceRecord.HandlerFrom]).
func (z *Zone) Handler(rr *zone.ResourceRecord) zone.RecordHandler {
	return rr.HandlerFrom(z.Registry())
}

// SetClock makes [Zone.VerifyRRSIG] reject an RRSIG whose validity
// window (RFC 4034 §3.1.5, RFC 4035 §5.3.1) does not contain now().
// Both ends are inclusive. With no clock set (the default, or nil) the
// window is not checked.
func (z *Zone) SetClock(now func() time.Time) { z.now = now }

// NewZone constructs an empty DNSSEC zone.
func NewZone() *Zone {
	return &Zone{Zone: &zone.Zone{}}
}

// wireHeaderForOwner emits the RR-header bytes
// (owner_name(wire) + type(uint16) + class(uint16)) for an explicit
// owner. Used by [Zone.CreateDigestTarget] when wildcard
// reconstruction overrides the rrset's literal owner.
func wireHeaderForOwner(owner string, rrtype, class uint16) ([]byte, error) {
	nameWire, err := wire.DomainNameToWire(owner)
	if err != nil {
		return nil, err
	}
	var b wire.Builder
	b.AppendBytes(nameWire)
	b.AppendUint16(rrtype)
	b.AppendUint16(class)
	return b.Clone(), nil
}

// Parent returns the parent zone, or nil if this zone is the top of the
// configured chain (e.g. the root or an unattached trust anchor).
func (z *Zone) Parent() *Zone { return z.parent }

// SetParent attaches a parent zone. In [KeyModeKSK] a key is
// authenticated by a DS record at its owner name in the parent; the
// caller is responsible for having validated that DS rrset.
func (z *Zone) SetParent(p *Zone) { z.parent = p }

// AddSEP records name as a Secure Entry Point, reported back by
// [Zone.IsSecureEntryPoint].
//
// Deprecated: the mark no longer authenticates anything. Up to v0.9.0
// it made every DNSKEY owned by name pass as a KSK, so a key injected
// into the DNSKEY rrset was trusted too. Authenticate the specific key
// with [Zone.AddTrustedKey] instead.
func (z *Zone) AddSEP(name string) {
	z.seps = append(z.seps, name)
}

// IsSecureEntryPoint reports whether name was recorded with
// [Zone.AddSEP]. It has no bearing on validation.
func (z *Zone) IsSecureEntryPoint(name string) bool {
	return slices.Contains(z.seps, name)
}

// AddTrustedKey authenticates key as a key-signing key of the zone at
// its owner name, as a trust anchor or a DS match established by the
// caller does. In [KeyModeKSK] an RRSIG then verifies when its
// signature verifies under a DNSKEY equal to key: same owner name
// (compared canonically), flags, protocol, algorithm and public key.
// A copy of key is kept; later changes to key do not affect it.
func (z *Zone) AddTrustedKey(key *DNSKey) {
	z.trusted = append(z.trusted, key.Clone().(*DNSKey))
}

// IsTrustedKey reports whether key equals a key added with
// [Zone.AddTrustedKey].
func (z *Zone) IsTrustedKey(key *DNSKey) bool {
	return slices.ContainsFunc(z.trusted, func(t *DNSKey) bool { return sameKey(t, key) })
}

// sameKey reports whether a and b are the same DNSKEY: same owner name
// and RDATA.
func sameKey(a, b *DNSKey) bool {
	return EqualCanonicalNames(a.Label(), b.Label()) &&
		a.Flags == b.Flags && a.Protocol == b.Protocol && a.Algorithm == b.Algorithm &&
		bytes.Equal(a.KeyData, b.KeyData)
}

// FindRRSIGs returns all RRSIG handlers in this zone that cover the
// (name, typeCovered) RRset. If signer is non-empty it additionally
// filters by signer name.
func (z *Zone) FindRRSIGs(name string, typeCovered uint16, signer string) []*RRSig {
	candidates := z.FindRRSet(name, types.TypeRRSIG)
	var out []*RRSig
	for _, rr := range candidates {
		h, ok := z.Handler(rr).(*RRSig)
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

// FindDNSKeys returns every DNSKEY at signerName with the given key tag
// and algorithm, in zone order. Key tags are not unique (RFC 4035
// §5.3.1), so a signature must be tried against each of them.
func (z *Zone) FindDNSKeys(signerName string, keyTag uint16, algorithm uint8) []*DNSKey {
	var out []*DNSKey
	for _, rr := range z.FindRRSet(signerName, types.TypeDNSKEY) {
		h, ok := z.Handler(rr).(*DNSKey)
		if ok && h.KeyTag == keyTag && h.Algorithm == algorithm {
			out = append(out, h)
		}
	}
	return out
}

// FindDNSKey returns the first DNSKEY at signerName whose KeyTag
// matches. Pass keyTag = 0 to accept any tag. Several keys can share a
// tag; [Zone.FindDNSKeys] returns all of them.
func (z *Zone) FindDNSKey(signerName string, keyTag uint16) *DNSKey {
	candidates := z.FindRRSet(signerName, types.TypeDNSKEY)
	for _, rr := range candidates {
		h, ok := z.Handler(rr).(*DNSKey)
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

	// RFC 4035 §5.3.2: when RRSIG.Labels is fewer than the number of
	// labels in the rrset's owner name, the answer was synthesised by
	// wildcard expansion. The verifier reconstructs the original
	// wildcard owner ("*." + the right-most RRSIG.Labels labels of
	// name) and signs with that owner instead.
	digestOwner := rrset[0].Label
	if expected := LabelCount(name); int(rrsig.Labels) < expected {
		digestOwner = "*." + LastNLabels(name, int(rrsig.Labels))
	}

	headerBytes, err := wireHeaderForOwner(digestOwner, rrset[0].Type, rrset[0].Class)
	if err != nil {
		return nil, fmt.Errorf("%w: wire header: %v", ErrDNSSEC, err)
	}

	bodies := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		var b wire.Builder
		if err := rr.WireBodyWith(z.Registry(), &b); err != nil {
			return nil, fmt.Errorf("%w: wire body for %s: %v", ErrDNSSEC, rr.Label, err)
		}
		body := b.Clone()
		if len(body) < 2 {
			return nil, fmt.Errorf("%w: no encoder for %s %s (call %s, or keep the received RDATA with zone.NewResourceRecordWithRData)",
				ErrDNSSEC, rr.Label, types.RRTypeName(rr.Type), registrationFor(rr.Type, z.Registry() != zone.DefaultRegistry()))
		}
		bodies = append(bodies, body)
	}
	// RFC 4034 §6.3: order by the RDATA alone (each body carries a
	// 2-octet RDLENGTH prefix, which must not take part), and drop
	// duplicate RRs. Duplicates arise when two responses deposit the
	// same record, e.g. one NSEC answering both a DS probe and the leaf
	// query. UPSTREAM_FEEDBACK.md UF-005.
	slices.SortFunc(bodies, func(a, b []byte) int { return bytes.Compare(a[2:], b[2:]) })
	bodies = slices.CompactFunc(bodies, bytes.Equal)

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

// registrationFor names the call that registers an encoder for rrtype,
// in the default registry or (ownRegistry) in the zone's own one.
func registrationFor(rrtype uint16, ownRegistry bool) string {
	switch rrtype {
	case types.TypeDNSKEY, types.TypeCDNSKEY, types.TypeRRSIG, types.TypeDS, types.TypeCDS,
		types.TypeNSEC, types.TypeNSEC3, types.TypeNSEC3PARAM:
		if ownRegistry {
			return "dnssec.RegisterHandlersInto on the zone's registry"
		}
		return "dnssec.RegisterHandlers"
	}
	if ownRegistry {
		return "zone.RegisterHandlersInto on the zone's registry, e.g. verifier.WithZoneHandlers"
	}
	return "zone.RegisterHandlers"
}

// VerifyRRSIG checks one RRSIG against the RRset it covers. Returns
// (true, nil) on success; (false, nil) when verification fails for a
// non-erroneous reason (missing key, signature mismatch); (false, err)
// when the verification could not be attempted at all.
// [Zone.CheckRRSIG] makes the same check and says why it failed.
func (z *Zone) VerifyRRSIG(name string, typeCovered uint16, rrsig *RRSig, mode KeyVerifyMode) (bool, error) {
	s, err := z.CheckRRSIG(name, typeCovered, rrsig, mode)
	return s == SigVerified, err
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

// verifyKSK reports whether dnskey is an authenticated Key-Signing
// Key: added with [Zone.AddTrustedKey], or matching a DS record in the
// parent zone. The SEP flag is not consulted.
func (z *Zone) verifyKSK(dnskey *DNSKey) (bool, error) {
	if z.IsTrustedKey(dnskey) {
		return true, nil
	}
	return z.verifyDelegationSigner(dnskey)
}

// verifyZSK reports whether dnskey is a valid Zone-Signing Key: the
// DNSKEY rrset at its owner name, of which it is a member, verifies
// under an authenticated KSK.
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

// verifyDelegationSigner reports whether dnskey matches a DS record at
// its owner name in the parent zone. A zone without a parent has no DS
// to match: a DS at a zone's own apex is never consulted.
func (z *Zone) verifyDelegationSigner(dnskey *DNSKey) (bool, error) {
	if z.parent == nil {
		return false, nil
	}
	dsSet := z.parent.FindRRSet(dnskey.Label(), types.TypeDS)
	if len(dsSet) == 0 {
		return false, nil
	}

	for _, rr := range dsSet {
		ds, ok := z.Handler(rr).(*DS)
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

	sigB64 := base64.StdEncoding.EncodeToString(signature)
	value := fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
		types.RRTypeName(typeCovered), key.Algorithm, rrsig.Labels, ttl, expire, inception,
		key.KeyTag, key.Label(), sigB64)
	return zone.NewResourceRecord(name, ttl, "IN", "RRSIG", value)
}
