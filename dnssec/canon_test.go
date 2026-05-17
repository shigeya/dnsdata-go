package dnssec_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
)

// TestCompareCanonicalNames_RFC4034Section6_1 walks the canonical
// ordering example given verbatim in RFC 4034 §6.1 and asserts the
// returned comparator places each pair in the listed order.
func TestCompareCanonicalNames_RFC4034Section6_1(t *testing.T) {
	// In RFC order, ascending. \001 and \200 are octet escapes; the
	// RFC uses them as raw single-byte labels — we substitute the raw
	// bytes here because canonLabels treats the input as already
	// pre-escape-decoded.
	ordered := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\x01.z.example.",
		"*.z.example.",
		"\xc8.z.example.",
	}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		if got := dnssec.CompareCanonicalNames(a, b); got >= 0 {
			t.Errorf("CompareCanonicalNames(%q, %q) = %d, want < 0", a, b, got)
		}
		if got := dnssec.CompareCanonicalNames(b, a); got <= 0 {
			t.Errorf("CompareCanonicalNames(%q, %q) = %d, want > 0", b, a, got)
		}
	}
}

func TestCompareCanonicalNames_CaseFold(t *testing.T) {
	if got := dnssec.CompareCanonicalNames("EXAMPLE.com.", "example.COM."); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCompareCanonicalNames_RootEquivalence(t *testing.T) {
	for _, pair := range [][2]string{
		{"", "."},
		{".", ""},
		{".", "."},
	} {
		if got := dnssec.CompareCanonicalNames(pair[0], pair[1]); got != 0 {
			t.Errorf("CompareCanonicalNames(%q, %q) = %d, want 0", pair[0], pair[1], got)
		}
	}
}

func TestCompareCanonicalNames_ShorterIsLower(t *testing.T) {
	// "example." is a proper suffix-prefix relationship with
	// "a.example.": the shared right-most label is "example", and
	// "example." has nothing left to compare so it sorts lower.
	if got := dnssec.CompareCanonicalNames("example.", "a.example."); got >= 0 {
		t.Errorf("expected example. < a.example., got %d", got)
	}
}

func TestEqualCanonicalNames(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com.", "EXAMPLE.com.", true},
		{"example.com", "example.com.", true},
		{".", "", true},
		{"a.example.", "b.example.", false},
	}
	for _, c := range cases {
		if got := dnssec.EqualCanonicalNames(c.a, c.b); got != c.want {
			t.Errorf("EqualCanonicalNames(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
