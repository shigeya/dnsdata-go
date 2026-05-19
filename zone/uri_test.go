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

// Ported from dnsdata-js/packages/core/tests/zone/rr/uri_rr.spec.ts.

func TestParseURI_HTTP(t *testing.T) {
	v := `10 1 "http://www.example.com/path"`
	rr := newRR(t, "_http._tcp.example.com.", 3600, "IN", "URI", v)
	h, err := zone.ParseURI(rr, v)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if h.Priority != 10 || h.Weight != 1 || h.Target != "http://www.example.com/path" {
		t.Errorf("parsed = {%d %d %q}, want {10 1 %q}", h.Priority, h.Weight, h.Target, "http://www.example.com/path")
	}
}

func TestParseURI_FTP(t *testing.T) {
	v := `20 10 "ftp://ftp.example.com/public"`
	h, err := zone.ParseURI(nil, v)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if h.Priority != 20 || h.Weight != 10 || h.Target != "ftp://ftp.example.com/public" {
		t.Errorf("parsed = {%d %d %q}", h.Priority, h.Weight, h.Target)
	}
}

func TestParseURI_Malformed(t *testing.T) {
	for _, v := range []string{
		"",
		`10 1 http://example.com`,           // missing quotes
		`10 "http://example.com"`,           // missing weight
		`abc 1 "http://example.com"`,        // priority not numeric
		`10 abc "http://example.com"`,       // weight not numeric
		`70000 1 "http://example.com"`,      // priority overflows uint16
	} {
		if _, err := zone.ParseURI(nil, v); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseURI(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestURI_WireBody(t *testing.T) {
	v := `10 1 "http://www.example.com/"`
	h, err := zone.ParseURI(nil, v)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	target := []byte("http://www.example.com/")
	expectedRdlen := uint16(2 + 2 + len(target))
	if got := binary.BigEndian.Uint16(out[0:2]); got != expectedRdlen {
		t.Errorf("rdlen = %d, want %d", got, expectedRdlen)
	}
	if got := binary.BigEndian.Uint16(out[2:4]); got != 10 {
		t.Errorf("priority = %d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(out[4:6]); got != 1 {
		t.Errorf("weight = %d, want 1", got)
	}
	if !bytes.Equal(out[6:], target) {
		t.Errorf("target = %q, want %q", out[6:], target)
	}
	if len(out) != int(2+expectedRdlen) {
		t.Errorf("total length = %d, want %d", len(out), 2+expectedRdlen)
	}
}

func TestURI_Clone(t *testing.T) {
	h, err := zone.ParseURI(nil, `10 1 "http://www.example.com/"`)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	cloned, ok := h.Clone().(*zone.URI)
	if !ok {
		t.Fatalf("Clone returned %T, want *zone.URI", h.Clone())
	}
	if cloned.Priority != h.Priority || cloned.Weight != h.Weight || cloned.Target != h.Target {
		t.Errorf("Clone fields differ")
	}
}

func TestZone_ReadString_URIRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
_http._tcp  IN  URI  10 1 "http://www.example.com/"
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("_http._tcp.example.com.", types.TypeURI)
	if rr == nil {
		t.Fatalf("URI record missing from zone")
	}
	h, ok := rr.Handler().(*zone.URI)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.URI", rr.Handler())
	}
	if h.Priority != 10 || h.Weight != 1 || h.Target != "http://www.example.com/" {
		t.Errorf("parsed = {%d %d %q}", h.Priority, h.Weight, h.Target)
	}
}
