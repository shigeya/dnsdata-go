package dnssec

import (
	"strings"

	"github.com/shigeya/dnsdata-go/zone"
)

// CompareCanonicalNames compares a and b in DNSSEC canonical name order
// per RFC 4034 §6.1: labels are compared right-to-left, case-folded to
// lower case, and a shorter ordered-prefix sorts lower than its
// extension. The return is the usual -1 / 0 / 1 convention.
//
// The trailing dot is treated as decoration: "com." and "com" compare
// equal, "" and "." both represent the root.
//
// Examples (from RFC 4034 §6.1):
//
//	example       < a.example
//	a.example     < yljkjljk.a.example
//	yljkjljk.a.example < Z.a.example   (lowercase folds the same)
//	Z.a.example   < zABC.a.EXAMPLE
//	zABC.a.EXAMPLE < z.example
//	z.example     < \001.z.example
//	\001.z.example < *.z.example
//	*.z.example   < \200.z.example
//
// It delegates to [zone.CompareCanonicalNames], which the zone package
// also uses for [zone.Zone.RecordsCanonical].
func CompareCanonicalNames(a, b string) int {
	return zone.CompareCanonicalNames(a, b)
}

// canonLabels splits name on "." after lower-casing and trimming the
// trailing root dot, then returns the labels in their original order
// (left-most first). An empty name or bare "." returns nil.
func canonLabels(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// EqualCanonicalNames reports whether a and b are equal in DNSSEC
// canonical-name order. Equivalent to CompareCanonicalNames(a, b) == 0
// but allocation-free for the common matching-owner case in NSEC
// lookups.
func EqualCanonicalNames(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// LabelCount returns the number of labels in name, excluding the root
// label. "example.com." and "example.com" both return 2; "." returns
// 0. Used by wildcard handling (RFC 4034 §3.1.3) and ancestor walks.
func LabelCount(name string) int {
	return len(canonLabels(name))
}

// LastNLabels returns the right-most n labels of name as a
// fully-qualified domain name (with trailing dot). Returns "." if n
// is zero or larger than the label count of name.
func LastNLabels(name string, n int) string {
	labels := canonLabels(name)
	if n <= 0 || n > len(labels) {
		return "."
	}
	return strings.Join(labels[len(labels)-n:], ".") + "."
}
