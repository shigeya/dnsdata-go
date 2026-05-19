package zone_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/openpgpkey_rr.spec.ts.

var (
	openpgpkeyTestBytes = []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	openpgpkeyTestB64   = base64.StdEncoding.EncodeToString(openpgpkeyTestBytes)
)

func TestParseOPENPGPKEY_Base64(t *testing.T) {
	rr := newRR(t, "abc._openpgpkey.example.com.", 3600, "IN", "OPENPGPKEY", openpgpkeyTestB64)
	h, err := zone.ParseOPENPGPKEY(rr, openpgpkeyTestB64)
	if err != nil {
		t.Fatalf("ParseOPENPGPKEY: %v", err)
	}
	if !bytes.Equal(h.KeyData, openpgpkeyTestBytes) {
		t.Errorf("KeyData = %x, want %x", h.KeyData, openpgpkeyTestBytes)
	}
}

func TestParseOPENPGPKEY_WhitespaceInBase64(t *testing.T) {
	// Zone files may have base64 split across lines.
	mid := len(openpgpkeyTestB64) / 2
	withSpaces := openpgpkeyTestB64[:mid] + "\n\t " + openpgpkeyTestB64[mid:]
	h, err := zone.ParseOPENPGPKEY(nil, withSpaces)
	if err != nil {
		t.Fatalf("ParseOPENPGPKEY: %v", err)
	}
	if !bytes.Equal(h.KeyData, openpgpkeyTestBytes) {
		t.Errorf("KeyData = %x, want %x", h.KeyData, openpgpkeyTestBytes)
	}
}

func TestParseOPENPGPKEY_EmptyRejected(t *testing.T) {
	for _, v := range []string{"", "   ", "\t\n  "} {
		_, err := zone.ParseOPENPGPKEY(nil, v)
		if !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseOPENPGPKEY(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestParseOPENPGPKEY_InvalidBase64(t *testing.T) {
	_, err := zone.ParseOPENPGPKEY(nil, "!!!not-base64!!!")
	if !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestOPENPGPKEY_WireBody(t *testing.T) {
	h, err := zone.ParseOPENPGPKEY(nil, openpgpkeyTestB64)
	if err != nil {
		t.Fatalf("ParseOPENPGPKEY: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlen(2) + key_data(5)
	if want := 2 + len(openpgpkeyTestBytes); len(out) != want {
		t.Fatalf("WireBody length = %d, want %d", len(out), want)
	}
	if rdlen := int(out[0])<<8 | int(out[1]); rdlen != len(openpgpkeyTestBytes) {
		t.Errorf("rdlen = %d, want %d", rdlen, len(openpgpkeyTestBytes))
	}
	if !bytes.Equal(out[2:], openpgpkeyTestBytes) {
		t.Errorf("key_data = %x, want %x", out[2:], openpgpkeyTestBytes)
	}
}

func TestOPENPGPKEY_Clone(t *testing.T) {
	h, err := zone.ParseOPENPGPKEY(nil, openpgpkeyTestB64)
	if err != nil {
		t.Fatalf("ParseOPENPGPKEY: %v", err)
	}
	cloned, ok := h.Clone().(*zone.OPENPGPKEY)
	if !ok {
		t.Fatalf("Clone returned %T, want *zone.OPENPGPKEY", h.Clone())
	}
	if !bytes.Equal(cloned.KeyData, h.KeyData) {
		t.Errorf("KeyData mismatch after Clone")
	}
	if len(cloned.KeyData) > 0 {
		cloned.KeyData[0] ^= 0xff
		if cloned.KeyData[0] == h.KeyData[0] {
			t.Errorf("Clone is not a deep copy")
		}
	}
}

func TestZone_ReadString_OPENPGPKEYRecord(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef})
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
abc._openpgpkey  IN  OPENPGPKEY  ` + b64 + `
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("abc._openpgpkey.example.com.", types.TypeOPENPGPKEY)
	if rr == nil {
		t.Fatalf("OPENPGPKEY record missing from zone")
	}
	h, ok := rr.Handler().(*zone.OPENPGPKEY)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.OPENPGPKEY", rr.Handler())
	}
	if len(h.KeyData) != 4 {
		t.Errorf("KeyData length = %d, want 4", len(h.KeyData))
	}
}
