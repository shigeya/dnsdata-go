package dnssec

import "strings"

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
func CompareCanonicalNames(a, b string) int {
	la := canonLabels(a)
	lb := canonLabels(b)

	// Compare label-by-label from the right (the rightmost label is the
	// most significant in canonical order).
	for i := 0; i < len(la) && i < len(lb); i++ {
		ai := la[len(la)-1-i]
		bi := lb[len(lb)-1-i]
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	// All shared labels matched. The shorter name sorts lower.
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	}
	return 0
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
