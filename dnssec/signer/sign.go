package signer

import (
	"fmt"
	"strings"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// Options controls [SignZone].
type Options struct {
	// Inception and Expiration bound every RRSIG. Both are required;
	// the signer never reads the clock, so windows in the past or the
	// future can be produced on purpose.
	Inception  time.Time
	Expiration time.Time
	// DNSKEYTTL is the TTL of the DNSKEY records added at the apex; 0
	// uses the SOA TTL, or 3600 without an SOA.
	DNSKEYTTL uint32
	// NSECTTL is passed to [BuildNSEC]; 0 derives it from the SOA.
	NSECTTL uint32
}

// SignZone returns a signed copy of z, whose records must all be at or
// below apex. The input is not modified.
//
// The copy gets the keys' DNSKEY records at the apex (added to any
// DNSKEY already there), an NSEC chain ([BuildNSEC]), and an RRSIG over
// every authoritative RRset: at a delegation point only DS and NSEC are
// signed, and glue below a delegation is not signed. With both KSKs
// (SEP flag) and ZSKs among keys, the KSKs sign the DNSKEY RRset and the
// ZSKs sign everything else; otherwise every key signs every RRset
// (combined signing keys). RRSIG / NSEC / NSEC3 / NSEC3PARAM records
// already in z are dropped, so a signed zone can be signed again.
//
// Like verifier.NewVerifier, SignZone registers the bundled zone and
// dnssec handlers (an explicit call, not an init() side effect), since
// every record must encode to be ordered and signed.
func SignZone(z *zone.Zone, apex string, keys []*Key, opts Options) (*zone.Zone, error) {
	registerHandlers()
	if err := checkSignArgs(apex, keys, opts); err != nil {
		return nil, err
	}
	out, err := copyUnsigned(z, apex)
	if err != nil {
		return nil, err
	}
	if err := addDNSKEYs(out, apex, keys, opts.DNSKEYTTL); err != nil {
		return nil, err
	}
	nsecs, err := BuildNSEC(out, apex, opts.NSECTTL)
	if err != nil {
		return nil, err
	}
	for _, rr := range nsecs {
		out.AddRR(rr)
	}
	sigs, err := signRRsets(out, apex, keys, opts)
	if err != nil {
		return nil, err
	}
	for _, rr := range sigs {
		out.AddRR(rr)
	}
	return out, nil
}

// registerHandlers installs the bundled RR handlers so that every
// record type the signer meets can be encoded.
func registerHandlers() {
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
}

func checkSignArgs(apex string, keys []*Key, opts Options) error {
	if !strings.HasSuffix(apex, ".") {
		return fmt.Errorf("%w: apex %q is not fully qualified", ErrSigner, apex)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no keys", ErrSigner)
	}
	for _, k := range keys {
		if !sameName(k.Owner, apex) {
			return fmt.Errorf("%w: key %d is for %s, not %s", ErrSigner, k.KeyTag(), k.Owner, apex)
		}
	}
	if opts.Inception.IsZero() || opts.Expiration.IsZero() {
		return fmt.Errorf("%w: Inception and Expiration are required", ErrSigner)
	}
	return nil
}

// copyUnsigned copies z without generated records, as fresh records.
func copyUnsigned(z *zone.Zone, apex string) (*zone.Zone, error) {
	out := &zone.Zone{}
	for _, rr := range z.AllRecords() {
		if isGeneratedType(rr.Type) {
			continue
		}
		if !isAtOrBelow(rr.Label, apex) {
			return nil, fmt.Errorf("%w: %s is outside the zone %s", ErrSigner, rr.Label, apex)
		}
		cp, err := zone.NewResourceRecord(rr.Label, rr.TTL, rr.Class, rr.Type, rr.Value)
		if err != nil {
			return nil, err
		}
		out.AddRR(cp)
	}
	return out, nil
}

func addDNSKEYs(out *zone.Zone, apex string, keys []*Key, ttl uint32) error {
	if ttl == 0 {
		ttl = defaultTTL
		if soa := soaAt(out, apex); soa != nil {
			ttl = soa.TTL
		}
	}
	existing := map[string]bool{}
	for _, rr := range out.FindRRSet(apex, types.TypeDNSKEY) {
		existing[rr.Value] = true
	}
	for _, k := range keys {
		if existing[k.DNSKEYValue()] {
			continue
		}
		rr, err := zone.NewResourceRecord(apex, ttl, types.ClassIN, types.TypeDNSKEY, k.DNSKEYValue())
		if err != nil {
			return err
		}
		out.AddRR(rr)
		existing[k.DNSKEYValue()] = true
	}
	return nil
}

// signRRsets returns the RRSIG records for every RRset that must be
// signed in out, whose NSEC chain is already in place.
func signRRsets(out *zone.Zone, apex string, keys []*Key, opts Options) ([]*zone.ResourceRecord, error) {
	v, err := newZoneView(out, apex)
	if err != nil {
		return nil, err
	}
	ksks, zsks := splitKeys(keys)
	dz := &dnssec.Zone{Zone: out}
	var sigs []*zone.ResourceRecord
	for _, owner := range v.owners {
		if v.isOccluded(owner) {
			continue
		}
		// newZoneView skips generated types, so NSEC is added here.
		for _, t := range append(v.types[strings.ToLower(owner)], types.TypeNSEC) {
			if v.isCut(owner) && t != types.TypeDS && t != types.TypeNSEC {
				continue
			}
			signers := zsks
			if t == types.TypeDNSKEY {
				signers = ksks
			}
			for _, k := range signers {
				rr, err := signRRset(dz, owner, t, apex, k, opts)
				if err != nil {
					return nil, err
				}
				sigs = append(sigs, rr)
			}
		}
	}
	return sigs, nil
}

// splitKeys returns (DNSKEY signers, other signers): KSKs and ZSKs when
// both kinds are present, otherwise all keys for both.
func splitKeys(keys []*Key) (ksks, zsks []*Key) {
	for _, k := range keys {
		if k.IsKSK() {
			ksks = append(ksks, k)
		} else {
			zsks = append(zsks, k)
		}
	}
	if len(ksks) == 0 || len(zsks) == 0 {
		return keys, keys
	}
	return ksks, zsks
}

// signRRset signs the (owner, rrtype) RRset of dz with k.
func signRRset(dz *dnssec.Zone, owner string, rrtype uint16, apex string, k *Key, opts Options) (*zone.ResourceRecord, error) {
	rrset := dz.FindRRSet(owner, rrtype)
	if len(rrset) == 0 {
		return nil, fmt.Errorf("%w: no %s RRset at %s", ErrSigner, types.RRTypeName(rrtype), owner)
	}
	ttl := rrset[0].TTL
	sig := &dnssec.RRSig{
		TypeCovered: rrtype,
		Algorithm:   k.Algorithm,
		Labels:      rrsigLabels(owner),
		OriginalTTL: ttl,
		Expire:      opts.Expiration.Unix(),
		Inception:   opts.Inception.Unix(),
		KeyTag:      k.KeyTag(),
		Signer:      apex,
	}
	digest, err := dz.CreateDigestTarget(sig, owner, rrtype)
	if err != nil {
		return nil, err
	}
	sk, err := k.signingKey()
	if err != nil {
		return nil, err
	}
	if sig.Signature, err = sk.Sign(digest); err != nil {
		return nil, fmt.Errorf("%w: sign %s/%s: %v", ErrSigner, owner, types.RRTypeName(rrtype), err)
	}
	return zone.NewResourceRecord(owner, ttl, types.ClassIN, types.TypeRRSIG, sig.ValueString())
}

// rrsigLabels is the RRSIG Labels field for owner (RFC 4034 §3.1.3):
// the label count without the root, and without a leading wildcard.
func rrsigLabels(owner string) uint8 {
	labels := labelsOf(owner)
	if len(labels) > 0 && labels[0] == "*" {
		return uint8(len(labels) - 1)
	}
	return uint8(len(labels))
}
