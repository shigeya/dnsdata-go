package zone_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/hinfo_rr.spec.ts.

func TestParseHINFO_QuotedStrings(t *testing.T) {
	v := `"INTEL-386" "UNIX"`
	rr := newRR(t, "host.example.com.", 3600, "IN", "HINFO", v)
	h, err := zone.ParseHINFO(rr, v)
	if err != nil {
		t.Fatalf("ParseHINFO: %v", err)
	}
	if h.CPU != "INTEL-386" || h.OS != "UNIX" {
		t.Errorf("parsed = {%q %q}", h.CPU, h.OS)
	}
}

func TestParseHINFO_UnquotedStrings(t *testing.T) {
	h, err := zone.ParseHINFO(nil, "INTEL-386 UNIX")
	if err != nil {
		t.Fatalf("ParseHINFO: %v", err)
	}
	if h.CPU != "INTEL-386" || h.OS != "UNIX" {
		t.Errorf("parsed = {%q %q}", h.CPU, h.OS)
	}
}

func TestParseHINFO_QuotedWithEscape(t *testing.T) {
	// `\"` inside quotes is a literal '"'.
	h, err := zone.ParseHINFO(nil, `"x86\"" "Linux"`)
	if err != nil {
		t.Fatalf("ParseHINFO: %v", err)
	}
	if h.CPU != `x86"` {
		t.Errorf("CPU = %q, want %q", h.CPU, `x86"`)
	}
}

func TestParseHINFO_OneStringRejected(t *testing.T) {
	if _, err := zone.ParseHINFO(nil, "CPU"); !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestHINFO_WireBody(t *testing.T) {
	h, err := zone.ParseHINFO(nil, `"CPU" "OS"`)
	if err != nil {
		t.Fatalf("ParseHINFO: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlen(2) + cpu_len(1)+"CPU"(3) + os_len(1)+"OS"(2) = 9
	if len(out) != 9 {
		t.Fatalf("WireBody length = %d, want 9", len(out))
	}
	if rdlen := binary.BigEndian.Uint16(out[0:2]); rdlen != 7 {
		t.Errorf("rdlen = %d, want 7", rdlen)
	}
	if out[2] != 3 || string(out[3:6]) != "CPU" {
		t.Errorf("cpu segment = %v %q, want 3 \"CPU\"", out[2], out[3:6])
	}
	if out[6] != 2 || string(out[7:9]) != "OS" {
		t.Errorf("os segment = %v %q, want 2 \"OS\"", out[6], out[7:9])
	}
}

func TestHINFO_WireBody_OverlongCPU(t *testing.T) {
	h := &zone.HINFO{CPU: string(make([]byte, 256)), OS: "ok"}
	var b wire.Builder
	if err := h.WireBody(&b); !errors.Is(err, zone.ErrRDataFormat) {
		t.Errorf("err = %v, want ErrRDataFormat", err)
	}
}

func TestHINFO_Clone(t *testing.T) {
	h, err := zone.ParseHINFO(nil, `"CPU" "OS"`)
	if err != nil {
		t.Fatalf("ParseHINFO: %v", err)
	}
	cloned, ok := h.Clone().(*zone.HINFO)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.CPU != h.CPU || cloned.OS != h.OS {
		t.Errorf("Clone fields differ")
	}
}

func TestZone_ReadString_HINFORecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
host  IN  HINFO  INTEL-386 UNIX
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("host.example.com.", types.TypeHINFO)
	if rr == nil {
		t.Fatalf("HINFO record missing from zone")
	}
	h, ok := rr.Handler().(*zone.HINFO)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.HINFO", rr.Handler())
	}
	if h.CPU != "INTEL-386" || h.OS != "UNIX" {
		t.Errorf("parsed = {%q %q}", h.CPU, h.OS)
	}
}
