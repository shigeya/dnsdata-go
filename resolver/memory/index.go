package memory

import (
	"fmt"
	"slices"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// normalize lower-cases name and makes it fully qualified.
func normalize(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// labels returns name's labels, left-most first; the root has none.
func labels(name string) []string {
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, ".")
}

// isAtOrBelow reports whether name equals ancestor or descends from it.
// Both must be normalized.
func isAtOrBelow(name, ancestor string) bool {
	n, a := labels(name), labels(ancestor)
	return len(n) >= len(a) && slices.Equal(n[len(n)-len(a):], a)
}

// parent returns the name one label shorter; the root is its own parent.
func parent(name string) string {
	l := labels(name)
	if len(l) <= 1 {
		return "."
	}
	return strings.Join(l[1:], ".") + "."
}

// wildcardOf returns `*.<name>`.
func wildcardOf(name string) string {
	if name == "." {
		return "*."
	}
	return "*." + name
}

// nsecEntry is an NSEC record at owner, parsed for range checks.
type nsecEntry struct {
	owner string
	nsec  *dnssec.NSEC
}

// zoneIndex is a read-only view of one zone, built once by [New].
type zoneIndex struct {
	apex    string
	byName  map[string][]*zone.ResourceRecord // owner → records
	covered map[*zone.ResourceRecord]uint16   // RRSIG → type covered
	exists  map[string]bool                   // owners and their ancestors down to the apex
	cuts    []string                          // delegation points
	nsecs   []nsecEntry
}

func newZoneIndex(apex string, z *zone.Zone) (*zoneIndex, error) {
	idx := &zoneIndex{
		apex:    apex,
		byName:  map[string][]*zone.ResourceRecord{},
		covered: map[*zone.ResourceRecord]uint16{},
		exists:  map[string]bool{},
	}
	for _, rr := range z.AllRecords() {
		if err := idx.add(rr); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func (idx *zoneIndex) add(rr *zone.ResourceRecord) error {
	owner := normalize(rr.Label)
	if !isAtOrBelow(owner, idx.apex) {
		return fmt.Errorf("%w: %s is outside the zone %s", ErrConfig, rr.Label, idx.apex)
	}
	idx.byName[owner] = append(idx.byName[owner], rr)
	for n := owner; !idx.exists[n]; n = parent(n) {
		idx.exists[n] = true
		if n == idx.apex {
			break
		}
	}
	switch rr.Type {
	case types.TypeRRSIG:
		sig, err := dnssec.ParseRRSig(nil, rr.Value)
		if err != nil {
			return fmt.Errorf("%w: RRSIG at %s: %v", ErrConfig, rr.Label, err)
		}
		idx.covered[rr] = sig.TypeCovered
	case types.TypeNSEC:
		n, err := dnssec.ParseNSEC(nil, rr.Value)
		if err != nil {
			return fmt.Errorf("%w: NSEC at %s: %v", ErrConfig, rr.Label, err)
		}
		idx.nsecs = append(idx.nsecs, nsecEntry{owner: owner, nsec: n})
	case types.TypeNS:
		if owner != idx.apex && !slices.Contains(idx.cuts, owner) {
			idx.cuts = append(idx.cuts, owner)
		}
	}
	return nil
}

// rrset returns the records of type t at name.
func (idx *zoneIndex) rrset(name string, t uint16) []*zone.ResourceRecord {
	var out []*zone.ResourceRecord
	for _, rr := range idx.byName[name] {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

// withSigs returns the (name, t) RRset followed by the RRSIGs covering it.
func (idx *zoneIndex) withSigs(name string, t uint16) []*zone.ResourceRecord {
	out := idx.rrset(name, t)
	if len(out) == 0 {
		return nil
	}
	for _, rr := range idx.rrset(name, types.TypeRRSIG) {
		if idx.covered[rr] == t {
			out = append(out, rr)
		}
	}
	return out
}

// cutAbove returns the delegation point closest to the apex at or
// above name, or "".
func (idx *zoneIndex) cutAbove(name string) string {
	best := ""
	for _, c := range idx.cuts {
		if isAtOrBelow(name, c) && (best == "" || len(labels(c)) < len(labels(best))) {
			best = c
		}
	}
	return best
}

// closestEncloser returns the deepest existing ancestor of name.
func (idx *zoneIndex) closestEncloser(name string) string {
	n := name
	for !idx.exists[n] && n != idx.apex && n != "." {
		n = parent(n)
	}
	return n
}

// nextCloser returns the ancestor of name one label below ce.
func nextCloser(name, ce string) string {
	l := labels(name)
	keep := len(labels(ce)) + 1
	return strings.Join(l[len(l)-keep:], ".") + "."
}

// coveringNSEC returns the NSEC (with signatures) whose range covers
// target, or nil.
func (idx *zoneIndex) coveringNSEC(target string) []*zone.ResourceRecord {
	for _, e := range idx.nsecs {
		if e.nsec.CoversName(e.owner, target) {
			return idx.withSigs(e.owner, types.TypeNSEC)
		}
	}
	return nil
}

// dnameAbove returns the owner of a DNAME strictly above name within
// the zone, or "".
func (idx *zoneIndex) dnameAbove(name string) string {
	for n := parent(name); isAtOrBelow(n, idx.apex); n = parent(n) {
		if len(idx.rrset(n, types.TypeDNAME)) > 0 {
			return n
		}
		if n == idx.apex {
			break
		}
	}
	return ""
}
