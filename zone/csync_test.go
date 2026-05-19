package zone_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/csync_rr.spec.ts.

func TestParseCSYNC_WithTypeList(t *testing.T) {
	// serial=66, flags=3 (immediate+soaminimum), types: A NS AAAA
	rr := newRR(t, "example.com.", 3600, "IN", "CSYNC", "66 3 A NS AAAA")
	h, err := zone.ParseCSYNC(rr, "66 3 A NS AAAA")
	if err != nil {
		t.Fatalf("ParseCSYNC: %v", err)
	}
	if h.SOASerial != 66 {
		t.Errorf("SOASerial = %d, want 66", h.SOASerial)
	}
	if h.Flags != 3 {
		t.Errorf("Flags = %d, want 3", h.Flags)
	}
	if !containsAll(h.CoveredTypes, []uint16{types.TypeA, types.TypeNS, types.TypeAAAA}) {
		t.Errorf("CoveredTypes = %v, want A NS AAAA", h.CoveredTypes)
	}
}

func TestParseCSYNC_NoTypes(t *testing.T) {
	h, err := zone.ParseCSYNC(nil, "100 1")
	if err != nil {
		t.Fatalf("ParseCSYNC: %v", err)
	}
	if h.SOASerial != 100 || h.Flags != 1 {
		t.Errorf("parsed = {%d %d}", h.SOASerial, h.Flags)
	}
	if len(h.CoveredTypes) != 0 {
		t.Errorf("CoveredTypes = %v, want empty", h.CoveredTypes)
	}
	if len(h.TypeBitmap) != 0 {
		t.Errorf("TypeBitmap length = %d, want 0", len(h.TypeBitmap))
	}
}

func TestParseCSYNC_UnknownTypeDropped(t *testing.T) {
	// TS parity: unknown mnemonics are dropped silently.
	h, err := zone.ParseCSYNC(nil, "1 0 A FAKETYPE NS")
	if err != nil {
		t.Fatalf("ParseCSYNC: %v", err)
	}
	if !containsAll(h.CoveredTypes, []uint16{types.TypeA, types.TypeNS}) {
		t.Errorf("CoveredTypes = %v, want only A NS", h.CoveredTypes)
	}
	for _, c := range h.CoveredTypes {
		if c == 0 {
			t.Errorf("dropped type leaked as 0 into CoveredTypes")
		}
	}
}

func TestParseCSYNC_Malformed(t *testing.T) {
	// "1 70000 A" overflows uint16 flags (max 65535); the other cases
	// stress missing fields and non-numeric headers.
	for _, v := range []string{"", "66", "abc 1", "1 abc", "1 70000 A"} {
		if _, err := zone.ParseCSYNC(nil, v); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseCSYNC(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestCSYNC_WireBody(t *testing.T) {
	h, err := zone.ParseCSYNC(nil, "66 3 A NS AAAA")
	if err != nil {
		t.Fatalf("ParseCSYNC: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := binary.BigEndian.Uint16(out[0:2])
	if want := uint16(6 + len(h.TypeBitmap)); rdlen != want {
		t.Errorf("rdlen = %d, want %d", rdlen, want)
	}
	if got := binary.BigEndian.Uint32(out[2:6]); got != 66 {
		t.Errorf("soa_serial = %d, want 66", got)
	}
	if got := binary.BigEndian.Uint16(out[6:8]); got != 3 {
		t.Errorf("flags = %d, want 3", got)
	}
	if len(out) != int(2+rdlen) {
		t.Errorf("total length = %d, want %d", len(out), 2+rdlen)
	}
	// Window 0 follows the header.
	if out[8] != 0 {
		t.Errorf("first bitmap window = %d, want 0", out[8])
	}
}

func TestCSYNC_WireBody_NoTypes(t *testing.T) {
	h, err := zone.ParseCSYNC(nil, "100 1")
	if err != nil {
		t.Fatalf("ParseCSYNC: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if len(out) != 2+4+2 {
		t.Fatalf("length = %d, want 8", len(out))
	}
	if rdlen := binary.BigEndian.Uint16(out[0:2]); rdlen != 6 {
		t.Errorf("rdlen = %d, want 6", rdlen)
	}
}

func TestCSYNC_Clone(t *testing.T) {
	h, err := zone.ParseCSYNC(nil, "66 3 A NS AAAA")
	if err != nil {
		t.Fatalf("ParseCSYNC: %v", err)
	}
	cloned, ok := h.Clone().(*zone.CSYNC)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.SOASerial != h.SOASerial || cloned.Flags != h.Flags {
		t.Errorf("Clone header differs")
	}
	cloned.TypeBitmap[0] ^= 0xff
	if cloned.TypeBitmap[0] == h.TypeBitmap[0] {
		t.Errorf("Clone is not a deep copy")
	}
}

func TestZone_ReadString_CSYNCRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
@  IN  CSYNC  66 3 A NS AAAA
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("example.com.", types.TypeCSYNC)
	if rr == nil {
		t.Fatalf("CSYNC record missing")
	}
	h, ok := rr.Handler().(*zone.CSYNC)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.CSYNC", rr.Handler())
	}
	if h.SOASerial != 66 || h.Flags != 3 {
		t.Errorf("parsed = {%d %d}", h.SOASerial, h.Flags)
	}
}

// containsAll returns true if got contains every element of want.
func containsAll(got, want []uint16) bool {
	in := make(map[uint16]bool, len(got))
	for _, v := range got {
		in[v] = true
	}
	for _, w := range want {
		if !in[w] {
			return false
		}
	}
	return true
}
