package dnssec_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestMain installs the DNSSEC handlers before any handler-registration
// tests run. Subsequent invocations of RegisterHandlers from other
// places are idempotent (zone overwrites existing entries) so this is
// safe in all orderings.
func TestMain(m *testing.M) {
	dnssec.RegisterHandlers()
	m.Run()
}

func TestRegisterHandlers_DNSKEY(t *testing.T) {
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "DNSKEY", sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if h == nil {
		t.Fatalf("Handler() = nil; RegisterHandlers did not install DNSKEY")
	}
	if _, ok := h.(*dnssec.DNSKey); !ok {
		t.Errorf("Handler() = %T, want *dnssec.DNSKey", h)
	}
}

func TestRegisterHandlers_RRSIG(t *testing.T) {
	rr, err := zone.NewResourceRecord("www.example.com.", 86400, "IN", "RRSIG", sampleRRSIGValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if h == nil {
		t.Fatalf("Handler() = nil")
	}
	if _, ok := h.(*dnssec.RRSig); !ok {
		t.Errorf("Handler() = %T, want *dnssec.RRSig", h)
	}
}

func TestRegisterHandlers_DS(t *testing.T) {
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "DS", sampleDSValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if h == nil {
		t.Fatalf("Handler() = nil")
	}
	if _, ok := h.(*dnssec.DS); !ok {
		t.Errorf("Handler() = %T, want *dnssec.DS", h)
	}
}

func TestRegisterHandlers_NSEC(t *testing.T) {
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "NSEC", "host.example.com. A NS RRSIG NSEC")
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if h == nil {
		t.Fatalf("Handler() = nil")
	}
	if _, ok := h.(*dnssec.NSEC); !ok {
		t.Errorf("Handler() = %T, want *dnssec.NSEC", h)
	}
}

func TestRegisterHandlers_NSEC3(t *testing.T) {
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "NSEC3", "1 0 10 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A NS")
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if _, ok := h.(*dnssec.NSEC3); !ok {
		t.Errorf("Handler() = %T, want *dnssec.NSEC3", h)
	}
}

func TestRegisterHandlers_CDS_ReusesDSHandler(t *testing.T) {
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "CDS", sampleDSValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if _, ok := h.(*dnssec.DS); !ok {
		t.Errorf("CDS Handler() = %T, want *dnssec.DS", h)
	}
}
