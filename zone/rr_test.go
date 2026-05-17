package zone_test

import (
	"bytes"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

func newRR(t *testing.T, label string, ttl uint32, class, rrtype any, value string) *zone.ResourceRecord {
	t.Helper()
	rr, err := zone.NewResourceRecord(label, ttl, class, rrtype, value)
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}
	return rr
}

func TestNewResourceRecord_StringClassAndType(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "A", "192.168.1.1")
	if rr.Label != "example.com." || rr.TTL != 3600 || rr.Class != types.ClassIN || rr.Type != types.TypeA || rr.Value != "192.168.1.1" {
		t.Errorf("fields mismatch: %+v", rr)
	}
}

func TestNewResourceRecord_NumericClassAndType(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, uint16(1), uint16(1), "192.168.1.1")
	if rr.Class != 1 || rr.Type != 1 {
		t.Errorf("class=%d type=%d, want 1 1", rr.Class, rr.Type)
	}
}

func TestResourceRecord_WireHeader(t *testing.T) {
	rr := newRR(t, "xp.net.", 3600, "IN", "A", "1.2.3.4")
	var b wire.Builder
	if err := rr.WireHeader(&b); err != nil {
		t.Fatalf("WireHeader: %v", err)
	}
	want := []byte{
		0x02, 0x78, 0x70, 0x03, 0x6e, 0x65, 0x74, 0x00, // xp.net.
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
	}
	if !bytes.Equal(b.Bytes(), want) {
		t.Errorf("got % x\nwant % x", b.Bytes(), want)
	}
}

func TestResourceRecord_WireBody_A(t *testing.T) {
	rr := newRR(t, "x.net.", 3600, "IN", "A", "192.168.0.1")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	want := []byte{0x00, 0x04, 0xc0, 0xa8, 0x00, 0x01}
	if !bytes.Equal(b.Bytes(), want) {
		t.Errorf("got % x\nwant % x", b.Bytes(), want)
	}
}

func TestResourceRecord_WireBody_NS(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "NS", "ns1.example.com.")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlength header
	if out[0] != 0x00 || out[1] != 17 {
		t.Errorf("rdlength = %d, want 17 (1+3 + 1+7 + 1+3 + 1)", out[1])
	}
}

func TestResourceRecord_WireBody_SOA(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "SOA",
		"ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	// rdlength(2) + mname(17) + rname(19) + 5*4 = 58
	if got := len(b.Bytes()); got != 58 {
		t.Errorf("length = %d, want 58", got)
	}
}

func TestResourceRecord_WireBody_AAAA(t *testing.T) {
	rr := newRR(t, "x.net.", 3600, "IN", "AAAA", "2001:db8::1")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if out[0] != 0x00 || out[1] != 0x10 {
		t.Errorf("rdlength = % x, want 00 10", out[:2])
	}
	if out[2] != 0x20 || out[3] != 0x01 || out[4] != 0x0d || out[5] != 0xb8 {
		t.Errorf("prefix = % x, want 20 01 0d b8", out[2:6])
	}
	if out[17] != 0x01 {
		t.Errorf("last byte = %x, want 01", out[17])
	}
}

func TestResourceRecord_WireBody_MX(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "MX", "10 mail.example.com.")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if out[0] != 0x00 || out[1] != 20 {
		t.Errorf("rdlength = %d, want 20 (2 + 18)", out[1])
	}
	if out[2] != 0x00 || out[3] != 10 {
		t.Errorf("pref = % x, want 00 0a", out[2:4])
	}
}

func TestResourceRecord_WireBody_TXT(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "TXT", `"v=spf1 include:example.com ~all"`)
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := uint16(out[0])<<8 | uint16(out[1])
	const txt = "v=spf1 include:example.com ~all"
	if rdlen != uint16(1+len(txt)) {
		t.Errorf("rdlen = %d, want %d", rdlen, 1+len(txt))
	}
	if int(out[2]) != len(txt) {
		t.Errorf("char-string length = %d, want %d", out[2], len(txt))
	}
}

func TestResourceRecord_WireBody_SRV(t *testing.T) {
	rr := newRR(t, "_sip._tcp.example.com.", 3600, "IN", "SRV", "10 60 5060 sip.example.com.")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := uint16(out[0])<<8 | uint16(out[1])
	if rdlen != 6+17 {
		t.Errorf("rdlen = %d, want 23", rdlen)
	}
	if !(out[2] == 0x00 && out[3] == 10 && out[4] == 0x00 && out[5] == 60 && out[6] == 0x13 && out[7] == 0xc4) {
		t.Errorf("header = % x, want 00 0a 00 3c 13 c4", out[2:8])
	}
}

func TestResourceRecord_WireBody_CAA(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "CAA", `0 issue "letsencrypt.org"`)
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := uint16(out[0])<<8 | uint16(out[1])
	if rdlen != 22 {
		t.Errorf("rdlen = %d, want 22 (flags+taglen+\"issue\"+\"letsencrypt.org\")", rdlen)
	}
	if out[2] != 0 {
		t.Errorf("flags = %d, want 0", out[2])
	}
	if out[3] != 5 {
		t.Errorf("tag length = %d, want 5", out[3])
	}
}

func TestResourceRecord_WireBody_CNAME(t *testing.T) {
	rr := newRR(t, "www.example.com.", 3600, "IN", "CNAME", "example.com.")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if out[0] != 0x00 || out[1] != 13 {
		t.Errorf("rdlength = %d, want 13", out[1])
	}
}

func TestResourceRecord_WireBody_DNAME(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "DNAME", "example.net.")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if out[0] != 0x00 || out[1] != 13 {
		t.Errorf("rdlength = %d, want 13", out[1])
	}
}

func TestResourceRecord_String(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "A", "1.2.3.4")
	if got, want := rr.String(), "example.com. 3600 IN A 1.2.3.4"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
