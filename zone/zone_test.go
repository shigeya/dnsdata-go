package zone_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

func TestZone_AddAndFind(t *testing.T) {
	var z zone.Zone
	if _, err := z.AddRRFromParts("example.com.", 3600, "IN", "A", "1.2.3.4"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := z.AddRRFromParts("example.com.", 3600, "IN", "A", "5.6.7.8"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := z.AddRRFromParts("example.com.", 3600, "IN", "NS", "ns1.example.com."); err != nil {
		t.Fatalf("add: %v", err)
	}

	if z.FindRR("example.com.", types.TypeA) == nil {
		t.Errorf("FindRR(A) returned nil")
	}
	if got := z.FindRR("example.com.", types.TypeA).Value; got != "1.2.3.4" {
		t.Errorf("first A value = %q, want 1.2.3.4", got)
	}
	if got := len(z.FindRRSet("example.com.", types.TypeA)); got != 2 {
		t.Errorf("A RRset size = %d, want 2", got)
	}
	if got := len(z.FindRRSet("example.com.", types.TypeNS)); got != 1 {
		t.Errorf("NS RRset size = %d, want 1", got)
	}
	if z.FindRR("notexist.com.", types.TypeA) != nil {
		t.Errorf("FindRR(notexist) returned non-nil")
	}
}

func TestZone_ReadString_BasicMasterFile(t *testing.T) {
	zoneText := `
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
example.com. 3600 IN A 93.184.216.34
example.com. 3600 IN AAAA 2606:2800:220:1:248:1893:25c8:1946
www.example.com. 300 IN CNAME example.com.
`
	var z zone.Zone
	if err := z.ReadString(zoneText); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if z.FindRR("example.com.", types.TypeSOA) == nil {
		t.Errorf("SOA missing")
	}
	if got := len(z.FindRRSet("example.com.", types.TypeNS)); got != 2 {
		t.Errorf("NS count = %d, want 2", got)
	}
	if got := z.FindRR("example.com.", types.TypeA).Value; got != "93.184.216.34" {
		t.Errorf("A = %q", got)
	}
	if got := z.FindRR("www.example.com.", types.TypeCNAME).Value; got != "example.com." {
		t.Errorf("CNAME = %q", got)
	}
}

func TestZone_ReadString_Comments(t *testing.T) {
	zoneText := `
example.com. 3600 IN A 1.2.3.4 ; trailing comment
; whole-line comment
example.com. 3600 IN NS ns1.example.com.
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if got := z.FindRR("example.com.", types.TypeA); got == nil || got.Value != "1.2.3.4" {
		t.Errorf("A record: %v", got)
	}
	if z.FindRR("example.com.", types.TypeNS) == nil {
		t.Errorf("NS missing")
	}
}

func TestZone_ReadString_ParenContinuation(t *testing.T) {
	zoneText := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
    2021010101
    3600
    900
    604800
    86400
)
example.com. 3600 IN A 1.2.3.4
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if z.FindRR("example.com.", types.TypeSOA) == nil {
		t.Errorf("SOA missing")
	}
	if z.FindRR("example.com.", types.TypeA) == nil {
		t.Errorf("A missing")
	}
}

func TestZone_ReadString_LeadingWhitespaceLabel(t *testing.T) {
	zoneText := `example.com. 3600 IN A 1.2.3.4
                 3600 IN A 5.6.7.8
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if got := len(z.FindRRSet("example.com.", types.TypeA)); got != 2 {
		t.Errorf("A count = %d, want 2", got)
	}
}

func TestZone_ReadString_ImplicitClass(t *testing.T) {
	zoneText := "example.com. 3600 A 1.2.3.4\n"
	var z zone.Zone
	_ = z.ReadString(zoneText)
	rr := z.FindRR("example.com.", types.TypeA)
	if rr == nil || rr.Value != "1.2.3.4" || rr.Class != types.ClassIN {
		t.Errorf("got %+v, want IN A 1.2.3.4", rr)
	}
}

func TestZone_ReadString_OriginDirective(t *testing.T) {
	zoneText := `$ORIGIN example.com.
@ 3600 IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
@ 3600 IN A 1.2.3.4
www 3600 IN A 5.6.7.8
ns1 3600 IN A 10.0.0.1
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if z.FindRR("example.com.", types.TypeSOA) == nil {
		t.Errorf("SOA missing")
	}
	if got := z.FindRR("example.com.", types.TypeA); got == nil || got.Value != "1.2.3.4" {
		t.Errorf("@ resolution: %v", got)
	}
	if got := z.FindRR("www.example.com.", types.TypeA); got == nil || got.Value != "5.6.7.8" {
		t.Errorf("relative resolution: %v", got)
	}
	if got := z.FindRR("ns1.example.com.", types.TypeA); got == nil || got.Value != "10.0.0.1" {
		t.Errorf("relative ns1: %v", got)
	}
}

func TestZone_ReadString_TTLDirective(t *testing.T) {
	zoneText := `$TTL 86400
example.com. IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
example.com. IN A 1.2.3.4
example.com. 300 IN A 5.6.7.8
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if got := z.FindRR("example.com.", types.TypeSOA); got == nil || got.TTL != 86400 {
		t.Errorf("SOA TTL: %v", got)
	}
	rrs := z.FindRRSet("example.com.", types.TypeA)
	if len(rrs) != 2 {
		t.Fatalf("A count = %d, want 2", len(rrs))
	}
	if rrs[0].TTL != 86400 {
		t.Errorf("first A TTL = %d, want 86400", rrs[0].TTL)
	}
	if rrs[1].TTL != 300 {
		t.Errorf("second A TTL = %d, want 300", rrs[1].TTL)
	}
}

func TestZone_ReadString_OriginAndTTLTogether(t *testing.T) {
	zoneText := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin 2021010101 3600 900 604800 86400
@ IN NS ns1
@ IN A 93.184.216.34
www IN A 93.184.216.35
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if z.FindRR("example.com.", types.TypeSOA) == nil {
		t.Errorf("SOA missing")
	}
	if got := z.FindRR("example.com.", types.TypeA); got == nil || got.TTL != 3600 {
		t.Errorf("A: %v", got)
	}
	if got := z.FindRR("www.example.com.", types.TypeA); got == nil || got.Value != "93.184.216.35" {
		t.Errorf("www: %v", got)
	}
}

func TestZone_ReadString_FQDNNotAffectedByOrigin(t *testing.T) {
	zoneText := `$ORIGIN example.com.
other.net. 3600 IN A 1.2.3.4
`
	var z zone.Zone
	_ = z.ReadString(zoneText)
	if got := z.FindRR("other.net.", types.TypeA); got == nil || got.Value != "1.2.3.4" {
		t.Errorf("FQDN ignored origin: %v", got)
	}
}

func TestZone_Print_FiltersByType(t *testing.T) {
	var z zone.Zone
	_, _ = z.AddRRFromParts("example.com.", 3600, "IN", "A", "1.2.3.4")
	_, _ = z.AddRRFromParts("example.com.", 3600, "IN", "NS", "ns1.example.com.")
	out := z.Print(types.TypeA)
	if got, want := out, "example.com. 3600 IN A 1.2.3.4"; got != want {
		t.Errorf("Print(A) = %q, want %q", got, want)
	}
}

func TestZone_AllRecords(t *testing.T) {
	var z zone.Zone
	_, _ = z.AddRRFromParts("example.com.", 3600, "IN", "A", "1.2.3.4")
	_, _ = z.AddRRFromParts("example.com.", 3600, "IN", "NS", "ns1.example.com.")
	if got := len(z.AllRecords()); got != 2 {
		t.Errorf("AllRecords = %d, want 2", got)
	}
}
