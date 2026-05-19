package zone_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/loc_rr.spec.ts.

const (
	locEquator   uint32 = 1 << 31  // 2^31
	locAltOffset uint32 = 10000000 // 100,000 m in cm
)

func TestParseLOC_FullDMS(t *testing.T) {
	// RFC 1876 §3 example: 42 21 54 N 71 06 18 W -24m 30m
	rr := newRR(t, "example.com.", 3600, "IN", "LOC", "42 21 54 N 71 06 18 W -24m 30m")
	h, err := zone.ParseLOC(rr, "42 21 54 N 71 06 18 W -24m 30m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	if h.Version != 0 {
		t.Errorf("Version = %d, want 0", h.Version)
	}
	if want := locEquator + 152514000; h.Latitude != want {
		t.Errorf("Latitude = %d, want %d", h.Latitude, want)
	}
	if want := locEquator - 255978000; h.Longitude != want {
		t.Errorf("Longitude = %d, want %d", h.Longitude, want)
	}
	if want := locAltOffset - 2400; h.Altitude != want {
		t.Errorf("Altitude = %d, want %d", h.Altitude, want)
	}
}

func TestParseLOC_DegreesOnly(t *testing.T) {
	h, err := zone.ParseLOC(nil, "42 N 71 W 0m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	if want := locEquator + 151200000; h.Latitude != want {
		t.Errorf("Latitude = %d, want %d", h.Latitude, want)
	}
}

func TestParseLOC_DegreesMinutes(t *testing.T) {
	h, err := zone.ParseLOC(nil, "42 21 N 71 06 W 100m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	if want := locEquator + 152460000; h.Latitude != want {
		t.Errorf("Latitude = %d, want %d", h.Latitude, want)
	}
}

func TestParseLOC_Defaults(t *testing.T) {
	// RFC 1876 §3 defaults: size=1m → 0x12, hp=10000m → 0x16, vp=10m → 0x13.
	h, err := zone.ParseLOC(nil, "0 N 0 E 0m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	if h.Size != 0x12 {
		t.Errorf("Size = 0x%02x, want 0x12", h.Size)
	}
	if h.HorizPre != 0x16 {
		t.Errorf("HorizPre = 0x%02x, want 0x16", h.HorizPre)
	}
	if h.VertPre != 0x13 {
		t.Errorf("VertPre = 0x%02x, want 0x13", h.VertPre)
	}
}

func TestParseLOC_SouthEast(t *testing.T) {
	h, err := zone.ParseLOC(nil, "33 51 36 S 151 12 40 E 50m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	if want := locEquator - 121896000; h.Latitude != want {
		t.Errorf("Latitude = %d, want %d", h.Latitude, want)
	}
	if want := locEquator + 544360000; h.Longitude != want {
		t.Errorf("Longitude = %d, want %d", h.Longitude, want)
	}
}

func TestParseLOC_Malformed(t *testing.T) {
	for _, v := range []string{
		"",
		"42 N 71 W", // missing altitude
		"42 X 71 W 0m", // bad direction
	} {
		if _, err := zone.ParseLOC(nil, v); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseLOC(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestLOC_WireBody(t *testing.T) {
	h, err := zone.ParseLOC(nil, "0 N 0 E 0m 1m 10000m 10m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if len(out) != 2+16 {
		t.Fatalf("length = %d, want 18", len(out))
	}
	if rdlen := binary.BigEndian.Uint16(out[0:2]); rdlen != 16 {
		t.Errorf("rdlen = %d, want 16", rdlen)
	}
	if out[2] != 0 {
		t.Errorf("version = %d, want 0", out[2])
	}
	if out[3] != 0x12 || out[4] != 0x16 || out[5] != 0x13 {
		t.Errorf("size/hp/vp = %02x/%02x/%02x, want 12/16/13", out[3], out[4], out[5])
	}
	if got := binary.BigEndian.Uint32(out[6:10]); got != locEquator {
		t.Errorf("latitude = %d, want %d", got, locEquator)
	}
	if got := binary.BigEndian.Uint32(out[10:14]); got != locEquator {
		t.Errorf("longitude = %d, want %d", got, locEquator)
	}
	if got := binary.BigEndian.Uint32(out[14:18]); got != locAltOffset {
		t.Errorf("altitude = %d, want %d", got, locAltOffset)
	}
}

func TestLOC_Clone(t *testing.T) {
	h, err := zone.ParseLOC(nil, "42 21 54 N 71 06 18 W -24m 30m")
	if err != nil {
		t.Fatalf("ParseLOC: %v", err)
	}
	cloned, ok := h.Clone().(*zone.LOC)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.Latitude != h.Latitude || cloned.Longitude != h.Longitude || cloned.Altitude != h.Altitude {
		t.Errorf("Clone fields differ")
	}
}

func TestZone_ReadString_LOCRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
@  IN  LOC  42 21 54 N 71 06 18 W -24m 30m
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("example.com.", types.TypeLOC)
	if rr == nil {
		t.Fatalf("LOC record missing")
	}
	h, ok := rr.Handler().(*zone.LOC)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.LOC", rr.Handler())
	}
	if h.Version != 0 {
		t.Errorf("Version = %d, want 0", h.Version)
	}
}
