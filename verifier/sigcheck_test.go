package verifier_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
)

func TestSigCheck_ResultConstantsMatchDNSSEC(t *testing.T) {
	for status, want := range map[dnssec.SigStatus]string{
		dnssec.SigVerified:             verifier.SigVerified,
		dnssec.SigExpired:              verifier.SigExpired,
		dnssec.SigNotYetValid:          verifier.SigNotYetValid,
		dnssec.SigUnsupportedAlgorithm: verifier.SigUnsupportedAlgorithm,
		dnssec.SigNoMatchingKey:        verifier.SigNoMatchingKey,
		dnssec.SigInvalid:              verifier.SigInvalid,
	} {
		if status.String() != want {
			t.Errorf("dnssec %q, verifier %q", status.String(), want)
		}
	}
}

// stepOf returns the chain step for zoneName, failing the test if absent.
func stepOf(t *testing.T, res *verifier.Result, zoneName string) verifier.ZoneStep {
	t.Helper()
	for _, s := range res.Chain {
		if s.Zone == zoneName {
			return s
		}
	}
	t.Fatalf("no step for %s in %+v", zoneName, res.Chain)
	return verifier.ZoneStep{}
}

// sigSummary renders a step's checks as "name/TYPE=result" in order.
func sigSummary(step verifier.ZoneStep) string {
	parts := make([]string, 0, len(step.Signatures))
	for _, s := range step.Signatures {
		parts = append(parts, s.Name+"/"+types.RRTypeName(s.RRType)+"="+s.Result)
	}
	return strings.Join(parts, " ")
}

func TestZoneStep_SignaturesOnASecureChain(t *testing.T) {
	f := newReasonFixture(t)
	res, err := f.validate(t, "www.example.com.")
	if err != nil || res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Validate: %v, %v", res.Verdict, err)
	}
	want := map[string]string{
		".":            "./DNSKEY=verified",
		"com.":         "com./DS=verified com./DNSKEY=verified",
		"example.com.": "example.com./DS=verified example.com./DNSKEY=verified www.example.com./A=verified",
	}
	for zoneName, w := range want {
		if got := sigSummary(stepOf(t, res, zoneName)); got != w {
			t.Errorf("%s: signatures %q, want %q", zoneName, got, w)
		}
	}

	a := stepOf(t, res, "example.com.").Signatures[2]
	wantA := verifier.SigCheck{
		Name: "www.example.com.", RRType: types.TypeA, KeyTag: f.leaf.key.KeyTag, Algorithm: 13,
		Signer: "example.com.", Inception: time.Unix(f.inception, 0).UTC(),
		Expiration: time.Unix(f.expire, 0).UTC(), Result: verifier.SigVerified,
	}
	if a != wantA {
		t.Errorf("answer SigCheck %+v, want %+v", a, wantA)
	}
	ds := stepOf(t, res, "com.").Signatures[0]
	if ds.Signer != "." || ds.KeyTag != f.root.key.KeyTag {
		t.Errorf("DS into com. signed by %s/%d, want ./%d", ds.Signer, ds.KeyTag, f.root.key.KeyTag)
	}
}

// TestZoneStep_ListsEveryRRSIG adds an expired second signature over
// the answer: both are listed, and the answer still verifies.
func TestZoneStep_ListsEveryRRSIG(t *testing.T) {
	f := newReasonFixture(t)
	old := time.Now().Add(-72 * time.Hour)
	f.leaf.addSignedRR(t, "www.example.com.", 300, types.TypeA, "192.0.2.10",
		old.Unix(), old.Add(24*time.Hour).Unix())
	f.resp[lookupKey{"www.example.com.", types.TypeA}] = rrsetWithSigs(f.leaf.z, "www.example.com.", types.TypeA)

	res, err := f.validate(t, "www.example.com.")
	if err != nil || res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Validate: %v, %v", res.Verdict, err)
	}
	got := sigSummary(stepOf(t, res, "example.com."))
	if !strings.Contains(got, "www.example.com./A=verified") || !strings.Contains(got, "www.example.com./A=expired") {
		t.Errorf("signatures %q, want the answer's verified and expired RRSIGs", got)
	}
}

// TestZoneStep_FailingZoneIsListed checks that the zone where
// validation failed has a step with the failing checks and no SignedBy.
func TestZoneStep_FailingZoneIsListed(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, f *reasonFixture) []verifier.Option
		zone    string
		summary string
	}{
		{"invalid DS signature", func(t *testing.T, f *reasonFixture) []verifier.Option {
			tamperRRSIG(t, withRRSIGsOnly(f.resp[lookupKey{"com.", types.TypeDS}])[0])
			return nil
		}, "com.", "com./DS=invalid"},
		{"expired root", func(t *testing.T, f *reasonFixture) []verifier.Option {
			return []verifier.Option{at(time.Now().Add(48 * time.Hour))}
		}, ".", "./DNSKEY=expired"},
		{"invalid answer signature", func(t *testing.T, f *reasonFixture) []verifier.Option {
			tamperRRSIG(t, withRRSIGsOnly(f.resp[lookupKey{"www.example.com.", types.TypeA}])[0])
			return nil
		}, "example.com.", "example.com./DS=verified example.com./DNSKEY=verified www.example.com./A=invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newReasonFixture(t)
			opts := c.setup(t, f)
			res, err := f.validate(t, "www.example.com.", opts...)
			if err != nil || res.Verdict != verifier.VerdictBogus {
				t.Fatalf("Validate: %v, %v", res.Verdict, err)
			}
			last := res.Chain[len(res.Chain)-1]
			if last.Zone != c.zone || sigSummary(last) != c.summary {
				t.Errorf("last step %s %q, want %s %q", last.Zone, sigSummary(last), c.zone, c.summary)
			}
			if c.zone != "example.com." && last.SignedBy != nil {
				t.Errorf("SignedBy %+v on the failing zone, want nil", last.SignedBy)
			}
		})
	}
}

func TestZoneStep_SignaturesJSON(t *testing.T) {
	f := newReasonFixture(t)
	res, err := f.validate(t, "www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"signatures":[`, `"name":"."`, `"rrType":48`, `"keyTag":`, `"algorithm":13`,
		`"signer":"."`, `"inception":"`, `"expiration":"`, `"result":"verified"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON %s lacks %s", b, key)
		}
	}
}
