package dnssec_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestVerifyRRSIG_BINDMixedCase verifies every RRSIG of a zone signed by
// BIND with mixed-case names. The NSEC next names and the SVCB / HTTPS
// targets are signed in their original case; lowercasing them made those
// signatures fail. UPSTREAM_FEEDBACK.md UF-008.
func TestVerifyRRSIG_BINDMixedCase(t *testing.T) {
	text, err := os.ReadFile(filepath.Join("..", "testdata", "bind", "case.example.zone"))
	if err != nil {
		t.Fatalf("read zone: %v", err)
	}
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
	z := dnssec.NewZone()
	if err := z.ReadStringStrict(string(text)); err != nil {
		t.Fatalf("ReadStringStrict: %v", err)
	}
	covered := map[uint16]int{}
	for _, rr := range z.AllRecords() {
		sig, ok := z.Handler(rr).(*dnssec.RRSig)
		if !ok {
			continue
		}
		covered[sig.TypeCovered]++
		ok, err := z.VerifyRRSIG(rr.Label, sig.TypeCovered, sig, dnssec.KeyModeNone)
		if err != nil || !ok {
			t.Errorf("%s RRSIG %s: verified=%v err=%v", rr.Label, types.RRTypeName(sig.TypeCovered), ok, err)
		}
	}
	for _, typ := range []uint16{types.TypeNSEC, types.TypeSVCB, types.TypeHTTPS, types.TypeCNAME} {
		if covered[typ] == 0 {
			t.Errorf("no RRSIG over %s in the vector", types.RRTypeName(typ))
		}
	}
}
