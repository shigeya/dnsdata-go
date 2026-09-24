package signer

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// defaultTTL is used for DNSKEY and NSEC records when the zone has no
// SOA to derive a TTL from.
const defaultTTL uint32 = 3600

// soaMinimumField is the index of MINIMUM among the SOA RDATA fields.
const soaMinimumField = 6

// isGeneratedType reports whether t is produced by signing and is
// therefore dropped from the input before (re-)signing.
func isGeneratedType(t uint16) bool {
	switch t {
	case types.TypeRRSIG, types.TypeNSEC, types.TypeNSEC3, types.TypeNSEC3PARAM:
		return true
	}
	return false
}

// labelsOf returns name's labels, lower-cased, right-most last; the root
// has none.
func labelsOf(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// isAtOrBelow reports whether name equals ancestor or is a descendant
// of it.
func isAtOrBelow(name, ancestor string) bool {
	n, a := labelsOf(name), labelsOf(ancestor)
	return len(n) >= len(a) && slices.Equal(n[len(n)-len(a):], a)
}

func sameName(a, b string) bool { return slices.Equal(labelsOf(a), labelsOf(b)) }

// zoneView is the part of a zone that signing looks at: the owners in
// canonical order, the types present at each, and the delegation points.
type zoneView struct {
	apex   string
	owners []string            // canonical order, each once
	types  map[string][]uint16 // lower-cased owner → types present
	cuts   []string            // delegation points (NS below the apex)
}

// newZoneView reads z, ignoring generated types, and rejects records
// outside apex.
func newZoneView(z *zone.Zone, apex string) (*zoneView, error) {
	recs, err := z.RecordsCanonical()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigner, err)
	}
	v := &zoneView{apex: apex, types: map[string][]uint16{}}
	for _, rr := range recs {
		if isGeneratedType(rr.Type) {
			continue
		}
		if !isAtOrBelow(rr.Label, apex) {
			return nil, fmt.Errorf("%w: %s is outside the zone %s", ErrSigner, rr.Label, apex)
		}
		key := strings.ToLower(rr.Label)
		if _, seen := v.types[key]; !seen {
			v.owners = append(v.owners, rr.Label)
		}
		if !slices.Contains(v.types[key], rr.Type) {
			v.types[key] = append(v.types[key], rr.Type)
		}
		if rr.Type == types.TypeNS && !sameName(rr.Label, apex) && !slices.Contains(v.cuts, rr.Label) {
			v.cuts = append(v.cuts, rr.Label)
		}
	}
	return v, nil
}

// isCut reports whether name is a delegation point.
func (v *zoneView) isCut(name string) bool {
	return slices.ContainsFunc(v.cuts, func(c string) bool { return sameName(c, name) })
}

// isOccluded reports whether name lies strictly below a delegation
// point (glue or occluded data): not authoritative, not signed, no NSEC.
func (v *zoneView) isOccluded(name string) bool {
	return slices.ContainsFunc(v.cuts, func(c string) bool {
		return !sameName(c, name) && isAtOrBelow(name, c)
	})
}

// BuildNSEC returns the NSEC chain for the zone at apex (RFC 4034 §4,
// RFC 4035 §2.3): one NSEC per authoritative owner name in canonical
// order, the last pointing back to the apex. Each bitmap lists the
// types at the owner plus RRSIG and NSEC; at a delegation point only NS
// and DS count; names below a delegation (glue) and empty non-terminals
// get none. Existing RRSIG / NSEC / NSEC3 records in z are ignored.
//
// ttl 0 uses min(SOA TTL, SOA MINIMUM) (RFC 9077), or 3600 without an
// SOA at the apex. It registers the bundled handlers, as [SignZone] does.
func BuildNSEC(z *zone.Zone, apex string, ttl uint32) ([]*zone.ResourceRecord, error) {
	registerHandlers()
	v, err := newZoneView(z, apex)
	if err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = nsecTTL(z, apex)
	}
	var owners []string
	for _, o := range v.owners {
		if !v.isOccluded(o) {
			owners = append(owners, o)
		}
	}
	out := make([]*zone.ResourceRecord, 0, len(owners))
	for i, owner := range owners {
		next := apex
		if i+1 < len(owners) {
			next = owners[i+1]
		}
		rr, err := zone.NewResourceRecord(owner, ttl, types.ClassIN, types.TypeNSEC, next+" "+v.bitmapText(owner))
		if err != nil {
			return nil, fmt.Errorf("%w: NSEC at %s: %v", ErrSigner, owner, err)
		}
		out = append(out, rr)
	}
	return out, nil
}

// bitmapText lists the types for owner's NSEC in presentation form.
func (v *zoneView) bitmapText(owner string) string {
	present := []uint16{types.TypeRRSIG, types.TypeNSEC}
	for _, t := range v.types[strings.ToLower(owner)] {
		if v.isCut(owner) && t != types.TypeNS && t != types.TypeDS {
			continue
		}
		present = append(present, t)
	}
	slices.Sort(present)
	names := make([]string, 0, len(present))
	for _, t := range slices.Compact(present) {
		names = append(names, types.RRTypeName(t))
	}
	return strings.Join(names, " ")
}

// soaAt returns the apex SOA record, or nil.
func soaAt(z *zone.Zone, apex string) *zone.ResourceRecord {
	for _, rr := range z.AllRecords() {
		if rr.Type == types.TypeSOA && sameName(rr.Label, apex) {
			return rr
		}
	}
	return nil
}

// nsecTTL is min(SOA TTL, SOA MINIMUM) per RFC 9077, or defaultTTL.
func nsecTTL(z *zone.Zone, apex string) uint32 {
	soa := soaAt(z, apex)
	if soa == nil {
		return defaultTTL
	}
	fields := strings.Fields(soa.Value)
	if len(fields) <= soaMinimumField {
		return soa.TTL
	}
	minimum, err := strconv.ParseUint(fields[soaMinimumField], 10, 32)
	if err != nil {
		return soa.TTL
	}
	return min(soa.TTL, uint32(minimum))
}
