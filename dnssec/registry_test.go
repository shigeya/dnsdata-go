package dnssec_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

func TestRegisterHandlersInto_InstallsTheDNSSECSet(t *testing.T) {
	reg := zone.NewRegistry()
	dnssec.RegisterHandlersInto(reg)
	for _, rrtype := range []uint16{
		types.TypeDNSKEY, types.TypeCDNSKEY, types.TypeRRSIG, types.TypeDS, types.TypeCDS,
		types.TypeNSEC, types.TypeNSEC3, types.TypeNSEC3PARAM,
	} {
		if reg.Lookup(rrtype) == nil {
			t.Errorf("%s not installed", types.RRTypeName(rrtype))
		}
	}
	if reg.Lookup(types.TypeTLSA) != nil {
		t.Error("TLSA installed; RegisterHandlersInto is the DNSSEC set only")
	}
}

// TestZone_UsesItsRegistry checks that a Zone resolves handlers through
// the Registry it was given, not the default one (which TestMain fills).
func TestZone_UsesItsRegistry(t *testing.T) {
	z, _ := signZone(t, "reg.example.")

	z.SetRegistry(zone.NewRegistry())
	if got := z.FindRRSIGs("www.reg.example.", types.TypeA, ""); len(got) != 0 {
		t.Errorf("FindRRSIGs with an empty registry = %d sigs, want 0", len(got))
	}
	if ok, _ := z.VerifyRRSet("www.reg.example.", types.TypeA, dnssec.KeyModeNone, ""); ok {
		t.Error("VerifyRRSet verified with an empty registry")
	}

	reg := zone.NewRegistry()
	dnssec.RegisterHandlersInto(reg)
	z.SetRegistry(reg)
	if z.Registry() != reg {
		t.Error("Registry() does not return the registry set")
	}
	ok, err := z.VerifyRRSet("www.reg.example.", types.TypeA, dnssec.KeyModeNone, "")
	if err != nil || !ok {
		t.Errorf("VerifyRRSet with a DNSSEC registry = %v, %v; want true", ok, err)
	}
}

func TestZone_RegistryDefaultsToDefault(t *testing.T) {
	if dnssec.NewZone().Registry() != zone.DefaultRegistry() {
		t.Error("a new Zone does not use the default registry")
	}
}
