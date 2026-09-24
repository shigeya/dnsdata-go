package zone_test

import (
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

func TestCompareCanonicalNames(t *testing.T) {
	// RFC 4034 §6.1 example, in order (escapes omitted).
	ordered := []string{
		"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", "*.z.example.",
	}
	for i := 0; i+1 < len(ordered); i++ {
		if zone.CompareCanonicalNames(ordered[i], ordered[i+1]) >= 0 {
			t.Errorf("%q should sort before %q", ordered[i], ordered[i+1])
		}
	}
	if zone.CompareCanonicalNames("Example.", "example") != 0 {
		t.Error("case and trailing dot must not matter")
	}
	if zone.CompareCanonicalNames(".", "com.") >= 0 {
		t.Error("root sorts first")
	}
}

func TestRecordsCanonical_Order(t *testing.T) {
	text := `$TTL 60
b.example. A 192.0.2.2
example. NS ns2.example.
a.example. TXT "x"
example. SOA ns1.example. h.example. 1 2 3 4 5
b.example. A 192.0.2.1
example. NS NS1.example.
a.example. A 192.0.2.3
a.example. TYPE65400 \# 1 00
b.example. A 192.0.2.1
`
	var z zone.Zone
	if err := z.ReadStringStrict(text); err != nil {
		t.Fatal(err)
	}
	got, err := z.PrintCanonical(0)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"example. 60 IN NS NS1.example.",
		"example. 60 IN NS ns2.example.",
		"example. 60 IN SOA ns1.example. h.example. 1 2 3 4 5",
		"a.example. 60 IN A 192.0.2.3",
		"a.example. 60 IN TXT \"x\"",
		`a.example. 60 IN TYPE65400 \# 1 00`,
		"b.example. 60 IN A 192.0.2.1",
		"b.example. 60 IN A 192.0.2.2",
	}, "\n")
	if got != want {
		t.Errorf("PrintCanonical:\n%s\nwant:\n%s", got, want)
	}

	onlyA, err := z.PrintCanonical(types.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(onlyA, "\n") != 2 || strings.Contains(onlyA, "NS") {
		t.Errorf("PrintCanonical(A) = %q", onlyA)
	}
}

func TestRecordsCanonical_Deterministic(t *testing.T) {
	build := func() string {
		var z zone.Zone
		for _, v := range []string{"192.0.2.9", "192.0.2.1", "192.0.2.5"} {
			if _, err := z.AddRRFromParts("x.example.", 60, "IN", "A", v); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := z.AddRRFromParts("y.example.", 60, "IN", "A", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		out, err := z.PrintCanonical(0)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := build()
	for range 20 {
		if got := build(); got != first {
			t.Fatalf("output changed between runs:\n%s\n---\n%s", first, got)
		}
	}
}

func TestRecordsCanonical_EncodeErrorIsReported(t *testing.T) {
	var z zone.Zone
	if _, err := z.AddRRFromParts("x.example.", 60, "IN", "A", "not-an-address"); err != nil {
		t.Fatal(err)
	}
	if _, err := z.RecordsCanonical(); err == nil {
		t.Error("RecordsCanonical: want error for an RR that does not encode")
	}
}

func TestRecordsCanonical_EmptyZone(t *testing.T) {
	var z zone.Zone
	recs, err := z.RecordsCanonical()
	if err != nil || len(recs) != 0 {
		t.Errorf("RecordsCanonical on empty zone = %v, %v", recs, err)
	}
}
