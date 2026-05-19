package zone_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/rp_rr.spec.ts.

func TestParseRP_TwoNames(t *testing.T) {
	v := "admin.example.com. info.example.com."
	rr := newRR(t, "example.com.", 3600, "IN", "RP", v)
	h, err := zone.ParseRP(rr, v)
	if err != nil {
		t.Fatalf("ParseRP: %v", err)
	}
	if h.Mbox != "admin.example.com." || h.TxtDName != "info.example.com." {
		t.Errorf("parsed = {%q %q}", h.Mbox, h.TxtDName)
	}
}

func TestParseRP_RootNames(t *testing.T) {
	// RFC 1183 §2.2: "." means no mailbox / no TXT records.
	h, err := zone.ParseRP(nil, ". .")
	if err != nil {
		t.Fatalf("ParseRP: %v", err)
	}
	if h.Mbox != "." || h.TxtDName != "." {
		t.Errorf("parsed = {%q %q}, want {. .}", h.Mbox, h.TxtDName)
	}
}

func TestParseRP_OneNameRejected(t *testing.T) {
	if _, err := zone.ParseRP(nil, "admin.example.com."); !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestRP_WireBody(t *testing.T) {
	h, err := zone.ParseRP(nil, "admin.example.com. info.example.com.")
	if err != nil {
		t.Fatalf("ParseRP: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// admin.example.com. → 5+admin + 7+example + 3+com + 0 = 19 octets
	// info.example.com.  → 4+info  + 7+example + 3+com + 0 = 18 octets
	expectedRdlen := uint16(19 + 18)
	if got := binary.BigEndian.Uint16(out[0:2]); got != expectedRdlen {
		t.Errorf("rdlen = %d, want %d", got, expectedRdlen)
	}
	if len(out) != int(2+expectedRdlen) {
		t.Errorf("total length = %d, want %d", len(out), 2+expectedRdlen)
	}
	if out[2] != 5 || string(out[3:8]) != "admin" {
		t.Errorf("first label = %d %q, want 5 \"admin\"", out[2], out[3:8])
	}
}

func TestRP_WireBody_RootNames(t *testing.T) {
	h, err := zone.ParseRP(nil, ". .")
	if err != nil {
		t.Fatalf("ParseRP: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlen(2) + root(1) + root(1)
	if len(out) != 4 {
		t.Fatalf("length = %d, want 4", len(out))
	}
	if rdlen := binary.BigEndian.Uint16(out[0:2]); rdlen != 2 {
		t.Errorf("rdlen = %d, want 2", rdlen)
	}
	if out[2] != 0 || out[3] != 0 {
		t.Errorf("root labels = %v %v, want 0 0", out[2], out[3])
	}
}

func TestRP_Clone(t *testing.T) {
	h, err := zone.ParseRP(nil, "admin.example.com. info.example.com.")
	if err != nil {
		t.Fatalf("ParseRP: %v", err)
	}
	cloned, ok := h.Clone().(*zone.RP)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.Mbox != h.Mbox || cloned.TxtDName != h.TxtDName {
		t.Errorf("Clone fields differ")
	}
}

func TestZone_ReadString_RPRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
@  IN  RP  admin.example.com. info.example.com.
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("example.com.", types.TypeRP)
	if rr == nil {
		t.Fatalf("RP record missing from zone")
	}
	h, ok := rr.Handler().(*zone.RP)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.RP", rr.Handler())
	}
	if h.Mbox != "admin.example.com." || h.TxtDName != "info.example.com." {
		t.Errorf("parsed = {%q %q}", h.Mbox, h.TxtDName)
	}
}
