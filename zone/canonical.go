package zone

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// CompareCanonicalNames compares a and b in DNSSEC canonical name order
// (RFC 4034 §6.1): labels compared right to left, case-folded to lower
// case, a name sorting before its own descendants. The trailing dot is
// optional; "" and "." both mean the root. Returns -1, 0 or 1.
func CompareCanonicalNames(a, b string) int {
	la, lb := canonicalLabels(a), canonicalLabels(b)
	for i := 0; i < len(la) && i < len(lb); i++ {
		if c := strings.Compare(la[len(la)-1-i], lb[len(lb)-1-i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(la), len(lb))
}

// canonicalLabels lower-cases name and splits it into labels, left-most
// first. The root yields no labels.
func canonicalLabels(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// canonicalRecord pairs a record with its encoded RDATA for sorting.
type canonicalRecord struct {
	rr    *ResourceRecord
	rdata []byte
}

// RecordsCanonical returns every record of the zone in RFC 4034 §6
// canonical order: owner name (§6.1), then type, then class, then the
// canonical (wire) RDATA (§6.3). Exact duplicates — same owner, type,
// class and RDATA octets — appear once (§6.3). The order does not depend
// on insertion order or map iteration, so the output can be fixed in
// test vectors.
//
// Returns an error if any record fails to encode; its RDATA order would
// otherwise be undefined.
func (z *Zone) RecordsCanonical() ([]*ResourceRecord, error) {
	all := z.AllRecords()
	recs := make([]canonicalRecord, 0, len(all))
	for _, rr := range all {
		var b wire.Builder
		if err := rr.WireBody(&b); err != nil {
			return nil, fmt.Errorf("%s: %w", rr.String(), err)
		}
		body := b.Clone()
		if len(body) >= 2 {
			body = body[2:]
		}
		recs = append(recs, canonicalRecord{rr: rr, rdata: body})
	}
	slices.SortStableFunc(recs, compareCanonicalRecords)
	recs = slices.CompactFunc(recs, func(a, b canonicalRecord) bool {
		return compareCanonicalRecords(a, b) == 0
	})
	out := make([]*ResourceRecord, len(recs))
	for i, r := range recs {
		out[i] = r.rr
	}
	return out, nil
}

func compareCanonicalRecords(a, b canonicalRecord) int {
	if c := CompareCanonicalNames(a.rr.Label, b.rr.Label); c != 0 {
		return c
	}
	if c := cmp.Compare(a.rr.Type, b.rr.Type); c != 0 {
		return c
	}
	if c := cmp.Compare(a.rr.Class, b.rr.Class); c != 0 {
		return c
	}
	return bytes.Compare(a.rdata, b.rdata)
}

// PrintCanonical is [Zone.Print] in the order of [Zone.RecordsCanonical]:
// one record per line in presentation form, filtered to onlyType when it
// is non-zero. The text is a valid master file for a general
// authoritative server when every owner is fully qualified.
func (z *Zone) PrintCanonical(onlyType uint16) (string, error) {
	recs, err := z.RecordsCanonical()
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(recs))
	for _, rr := range recs {
		if onlyType == 0 || rr.Type == onlyType {
			lines = append(lines, rr.String())
		}
	}
	return strings.Join(lines, "\n"), nil
}
