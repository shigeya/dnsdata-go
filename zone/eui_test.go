package zone_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/eui_rr.spec.ts.

func TestParseEUI48(t *testing.T) {
	rr := newRR(t, "host.example.com.", 86400, "IN", "EUI48", "00-00-5e-00-53-2a")
	h, err := zone.ParseEUI(rr, "00-00-5e-00-53-2a", 6)
	if err != nil {
		t.Fatalf("ParseEUI: %v", err)
	}
	want := []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a}
	if !bytes.Equal(h.Address, want) {
		t.Errorf("Address = %x, want %x", h.Address, want)
	}
	if h.ByteLen != 6 {
		t.Errorf("ByteLen = %d, want 6", h.ByteLen)
	}
}

func TestParseEUI48_UppercaseHex(t *testing.T) {
	h, err := zone.ParseEUI(nil, "AA-BB-CC-DD-EE-FF", 6)
	if err != nil {
		t.Fatalf("ParseEUI: %v", err)
	}
	if h.Address[0] != 0xaa || h.Address[5] != 0xff {
		t.Errorf("Address = %x", h.Address)
	}
}

func TestParseEUI48_InvalidLength(t *testing.T) {
	cases := []string{
		"",
		"00-00-5e-00-53",       // too few
		"00-00-5e-00-53-2a-ff", // too many
		"00-00-5e-00-53-zz",    // bad hex
		"00-005e-00-53-2a",     // an octet has 4 hex digits
	}
	for _, v := range cases {
		if _, err := zone.ParseEUI(nil, v, 6); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseEUI(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestEUI48_WireBody(t *testing.T) {
	h, err := zone.ParseEUI(nil, "00-00-5e-00-53-2a", 6)
	if err != nil {
		t.Fatalf("ParseEUI: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if len(out) != 2+6 {
		t.Fatalf("length = %d, want 8", len(out))
	}
	if rdlen := binary.BigEndian.Uint16(out[0:2]); rdlen != 6 {
		t.Errorf("rdlen = %d, want 6", rdlen)
	}
	if !bytes.Equal(out[2:], []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x2a}) {
		t.Errorf("address bytes = %x", out[2:])
	}
}

func TestParseEUI64(t *testing.T) {
	rr := newRR(t, "host.example.com.", 86400, "IN", "EUI64", "00-00-5e-ef-10-00-00-2a")
	h, err := zone.ParseEUI(rr, "00-00-5e-ef-10-00-00-2a", 8)
	if err != nil {
		t.Fatalf("ParseEUI: %v", err)
	}
	if h.ByteLen != 8 || len(h.Address) != 8 {
		t.Errorf("ByteLen = %d, len(Address) = %d, want 8/8", h.ByteLen, len(h.Address))
	}
	if h.Address[0] != 0x00 || h.Address[3] != 0xef || h.Address[7] != 0x2a {
		t.Errorf("Address = %x", h.Address)
	}
}

func TestParseEUI64_TooShort(t *testing.T) {
	if _, err := zone.ParseEUI(nil, "00-00-5e-ef-10-00-00", 8); !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestEUI64_WireBody(t *testing.T) {
	h, err := zone.ParseEUI(nil, "00-00-5e-ef-10-00-00-2a", 8)
	if err != nil {
		t.Fatalf("ParseEUI: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if len(out) != 2+8 {
		t.Fatalf("length = %d, want 10", len(out))
	}
	if rdlen := binary.BigEndian.Uint16(out[0:2]); rdlen != 8 {
		t.Errorf("rdlen = %d, want 8", rdlen)
	}
}

func TestEUI_Clone(t *testing.T) {
	h, err := zone.ParseEUI(nil, "00-00-5e-00-53-2a", 6)
	if err != nil {
		t.Fatalf("ParseEUI: %v", err)
	}
	cloned, ok := h.Clone().(*zone.EUI)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.ByteLen != h.ByteLen || !bytes.Equal(cloned.Address, h.Address) {
		t.Errorf("Clone fields differ")
	}
	cloned.Address[0] ^= 0xff
	if cloned.Address[0] == h.Address[0] {
		t.Errorf("Clone is not a deep copy")
	}
}

func TestZone_ReadString_EUI48Record(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 86400
host  IN  EUI48  00-00-5e-00-53-2a
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("host.example.com.", types.TypeEUI48)
	if rr == nil {
		t.Fatalf("EUI48 record missing")
	}
	h, ok := rr.Handler().(*zone.EUI)
	if !ok {
		t.Fatalf("Handler() returned %T", rr.Handler())
	}
	if h.ByteLen != 6 || len(h.Address) != 6 {
		t.Errorf("ByteLen = %d, len(Address) = %d", h.ByteLen, len(h.Address))
	}
}

func TestZone_ReadString_EUI64Record(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 86400
host  IN  EUI64  00-00-5e-ef-10-00-00-2a
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("host.example.com.", types.TypeEUI64)
	if rr == nil {
		t.Fatalf("EUI64 record missing")
	}
	h, ok := rr.Handler().(*zone.EUI)
	if !ok {
		t.Fatalf("Handler() returned %T", rr.Handler())
	}
	if h.ByteLen != 8 || len(h.Address) != 8 {
		t.Errorf("ByteLen = %d, len(Address) = %d", h.ByteLen, len(h.Address))
	}
}
