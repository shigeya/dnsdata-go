package zone_test

import (
	"encoding/hex"
	"testing"

	"github.com/shigeya/dnsdata-go/zone"
)

// TestWireBody_NameCase: a name in RDATA is lowercased only for the types
// on the RFC 4034 §6.2 list, whose canonical form folds it. NSEC (taken
// off the list by RFC 6840 §5.1) and SVCB / HTTPS (not on it) keep the
// case written in the presentation form. UPSTREAM_FEEDBACK.md UF-008.
func TestWireBody_NameCase(t *testing.T) {
	registerAllHandlers()
	cases := []struct {
		rrtype, value, want string
	}{
		{"SVCB", "1 Svc.Example.", "000103537663074578616d706c6500"},
		{"SVCB", "1 svc.example.", "000103737663076578616d706c6500"},
		{"HTTPS", "1 Svc.Example. alpn=h2", "000103537663074578616d706c650000010003026832"},
		{"NSEC", "Next.Example. A RRSIG", "044e657874074578616d706c65000006400000000002"},
		{"CNAME", "Svc.Example.", "03737663076578616d706c6500"},
		{"NS", "Svc.Example.", "03737663076578616d706c6500"},
		{"MX", "10 Svc.Example.", "000a03737663076578616d706c6500"},
		{"SRV", "0 0 25 Svc.Example.", "00000000001903737663076578616d706c6500"},
		{"RP", "Svc.Example. Txt.Example.", "03737663076578616d706c650003747874076578616d706c6500"},
		{"TXT", `"Svc"`, "03537663"},
	}
	for _, tc := range cases {
		t.Run(tc.rrtype+" "+tc.value, func(t *testing.T) {
			rr, err := zone.NewResourceRecord("case.example.", 300, "IN", tc.rrtype, tc.value)
			if err != nil {
				t.Fatalf("NewResourceRecord: %v", err)
			}
			if got := hex.EncodeToString(wireBodyOf(t, rr)); got != tc.want {
				t.Errorf("RDATA = %s, want %s", got, tc.want)
			}
		})
	}
}
