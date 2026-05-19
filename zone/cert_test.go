package zone_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/cert_rr.spec.ts.

var (
	certTestBytes = []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	certTestB64   = base64.StdEncoding.EncodeToString(certTestBytes)
)

func TestParseCERT_NumericType(t *testing.T) {
	v := "1 12345 8 " + certTestB64
	rr := newRR(t, "example.com.", 3600, "IN", "CERT", v)
	h, err := zone.ParseCERT(rr, v)
	if err != nil {
		t.Fatalf("ParseCERT: %v", err)
	}
	if h.CertType != 1 {
		t.Errorf("CertType = %d, want 1 (PKIX)", h.CertType)
	}
	if h.KeyTag != 12345 {
		t.Errorf("KeyTag = %d, want 12345", h.KeyTag)
	}
	if h.Algorithm != 8 {
		t.Errorf("Algorithm = %d, want 8", h.Algorithm)
	}
	if !bytes.Equal(h.Certificate, certTestBytes) {
		t.Errorf("Certificate = %x, want %x", h.Certificate, certTestBytes)
	}
}

func TestParseCERT_Mnemonics(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint16
	}{
		{"PKIX", 1},
		{"SPKI", 2},
		{"PGP", 3},
		{"IPKIX", 4},
		{"ISPKI", 5},
		{"IPGP", 6},
		{"ACPKIX", 7},
		{"IACPKIX", 8},
		{"URI", 253},
		{"OID", 254},
	} {
		v := tc.name + " 0 0 " + certTestB64
		h, err := zone.ParseCERT(nil, v)
		if err != nil {
			t.Errorf("ParseCERT(%s): %v", tc.name, err)
			continue
		}
		if h.CertType != tc.code {
			t.Errorf("CertType[%s] = %d, want %d", tc.name, h.CertType, tc.code)
		}
	}
}

func TestParseCERT_Malformed(t *testing.T) {
	for _, v := range []string{"", "1 2", "1 2 3", "BOGUS 1 1 abcd"} {
		if _, err := zone.ParseCERT(nil, v); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseCERT(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestParseCERT_SplitBase64Joined(t *testing.T) {
	// Long certificates often wrap across whitespace; the parser must
	// concatenate the trailing tokens before base64-decoding.
	mid := len(certTestB64) / 2
	v := "PKIX 12345 8 " + certTestB64[:mid] + " " + certTestB64[mid:]
	h, err := zone.ParseCERT(nil, v)
	if err != nil {
		t.Fatalf("ParseCERT split: %v", err)
	}
	if !bytes.Equal(h.Certificate, certTestBytes) {
		t.Errorf("split-base64 decoded = %x, want %x", h.Certificate, certTestBytes)
	}
}

func TestCERT_WireBody(t *testing.T) {
	h, err := zone.ParseCERT(nil, "1 12345 8 "+certTestB64)
	if err != nil {
		t.Fatalf("ParseCERT: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlen(2) + type(2) + key_tag(2) + algorithm(1) + cert(6) = 13
	if want := 2 + 2 + 2 + 1 + len(certTestBytes); len(out) != want {
		t.Fatalf("WireBody length = %d, want %d", len(out), want)
	}
	rdlen := binary.BigEndian.Uint16(out[0:2])
	if want := uint16(2 + 2 + 1 + len(certTestBytes)); rdlen != want {
		t.Errorf("rdlen = %d, want %d", rdlen, want)
	}
	if got := binary.BigEndian.Uint16(out[2:4]); got != 1 {
		t.Errorf("cert_type = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(out[4:6]); got != 12345 {
		t.Errorf("key_tag = %d, want 12345", got)
	}
	if out[6] != 8 {
		t.Errorf("algorithm = %d, want 8", out[6])
	}
	if !bytes.Equal(out[7:], certTestBytes) {
		t.Errorf("certificate = %x, want %x", out[7:], certTestBytes)
	}
}

func TestCERT_Clone(t *testing.T) {
	h, err := zone.ParseCERT(nil, "PKIX 12345 8 "+certTestB64)
	if err != nil {
		t.Fatalf("ParseCERT: %v", err)
	}
	cloned, ok := h.Clone().(*zone.CERT)
	if !ok {
		t.Fatalf("Clone returned %T, want *zone.CERT", h.Clone())
	}
	if cloned.CertType != h.CertType || cloned.KeyTag != h.KeyTag || cloned.Algorithm != h.Algorithm {
		t.Errorf("Clone header mismatch")
	}
	if !bytes.Equal(cloned.Certificate, h.Certificate) {
		t.Errorf("Certificate mismatch after Clone")
	}
	if len(cloned.Certificate) > 0 {
		cloned.Certificate[0] ^= 0xff
		if cloned.Certificate[0] == h.Certificate[0] {
			t.Errorf("Clone is not a deep copy")
		}
	}
}

func TestZone_ReadString_CERTRecord(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
@  IN  CERT  PKIX 12345 8 ` + b64 + `
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("example.com.", types.TypeCERT)
	if rr == nil {
		t.Fatalf("CERT record missing from zone")
	}
	h, ok := rr.Handler().(*zone.CERT)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.CERT", rr.Handler())
	}
	if h.CertType != 1 || h.KeyTag != 12345 || h.Algorithm != 8 {
		t.Errorf("parsed header = {%d %d %d}, want {1 12345 8}", h.CertType, h.KeyTag, h.Algorithm)
	}
}
