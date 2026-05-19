package zone_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/dane_rr.spec.ts.
// TLSA and SMIMEA share an identical wire format (RFC 6698 / RFC 8162);
// the JS spec asserts byte-for-byte equality between the two, and so
// does TestSMIMEA_MatchesTLSAWire below.

const (
	tlsaSHA256Hex = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566"
	tlsaValue     = "3 1 1 " + tlsaSHA256Hex // DANE-EE / SPKI / SHA-256
)

func TestParseTLSA_PresentationFormat(t *testing.T) {
	rr := newRR(t, "_443._tcp.example.com.", 3600, "IN", "TLSA", tlsaValue)
	h, err := zone.ParseTLSA(rr, tlsaValue)
	if err != nil {
		t.Fatalf("ParseTLSA: %v", err)
	}
	if h.Usage != 3 {
		t.Errorf("Usage = %d, want 3 (DANE-EE)", h.Usage)
	}
	if h.Selector != 1 {
		t.Errorf("Selector = %d, want 1 (SPKI)", h.Selector)
	}
	if h.MatchingType != 1 {
		t.Errorf("MatchingType = %d, want 1 (SHA-256)", h.MatchingType)
	}
	if got := hex.EncodeToString(h.CertificateAssociationData); got != tlsaSHA256Hex {
		t.Errorf("CertificateAssociationData hex = %q, want %q", got, tlsaSHA256Hex)
	}
}

func TestParseTLSA_Malformed(t *testing.T) {
	_, err := zone.ParseTLSA(nil, "invalid")
	if !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestParseTLSA_AcceptsWhitespaceInHex(t *testing.T) {
	rr := newRR(t, "_443._tcp.example.com.", 3600, "IN", "TLSA", "3 0 1 aabb ccdd eeff 0011")
	h, err := zone.ParseTLSA(rr, "3 0 1 aabb ccdd eeff 0011")
	if err != nil {
		t.Fatalf("ParseTLSA: %v", err)
	}
	if got := hex.EncodeToString(h.CertificateAssociationData); got != "aabbccddeeff0011" {
		t.Errorf("hex = %q, want aabbccddeeff0011", got)
	}
}

func TestTLSA_WireBody(t *testing.T) {
	rr := newRR(t, "_443._tcp.example.com.", 3600, "IN", "TLSA", tlsaValue)
	h, err := zone.ParseTLSA(rr, tlsaValue)
	if err != nil {
		t.Fatalf("ParseTLSA: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	dataLen := len(tlsaSHA256Hex) / 2
	// rdlen(2) + usage(1) + selector(1) + matchingType(1) + data
	if want := 2 + 3 + dataLen; len(out) != want {
		t.Errorf("WireBody length = %d, want %d", len(out), want)
	}
	if rdlen := int(out[0])<<8 | int(out[1]); rdlen != 3+dataLen {
		t.Errorf("rdlen = %d, want %d", rdlen, 3+dataLen)
	}
	if out[2] != 3 {
		t.Errorf("usage = %d, want 3", out[2])
	}
	if out[3] != 1 {
		t.Errorf("selector = %d, want 1", out[3])
	}
	if out[4] != 1 {
		t.Errorf("matchingType = %d, want 1", out[4])
	}
}

func TestTLSA_Clone(t *testing.T) {
	rr := newRR(t, "_443._tcp.example.com.", 3600, "IN", "TLSA", tlsaValue)
	h, err := zone.ParseTLSA(rr, tlsaValue)
	if err != nil {
		t.Fatalf("ParseTLSA: %v", err)
	}
	cloned, ok := h.Clone().(*zone.TLSA)
	if !ok {
		t.Fatalf("Clone returned %T, want *zone.TLSA", h.Clone())
	}
	if cloned.Usage != h.Usage || cloned.Selector != h.Selector || cloned.MatchingType != h.MatchingType {
		t.Errorf("clone header mismatch: got {%d %d %d}, want {%d %d %d}",
			cloned.Usage, cloned.Selector, cloned.MatchingType,
			h.Usage, h.Selector, h.MatchingType)
	}
	if !bytes.Equal(cloned.CertificateAssociationData, h.CertificateAssociationData) {
		t.Errorf("CertificateAssociationData mismatch after clone")
	}
	// Mutating the clone's data must not affect the original (independence).
	if len(cloned.CertificateAssociationData) > 0 {
		cloned.CertificateAssociationData[0] ^= 0xff
		if cloned.CertificateAssociationData[0] == h.CertificateAssociationData[0] {
			t.Errorf("Clone is not a deep copy: data backs the same slice")
		}
	}
}

func TestParseTLSA_AllUsageValues(t *testing.T) {
	for _, usage := range []int{0, 1, 2, 3} {
		v := strings.Replace("U 0 1 aabbccdd", "U", string(rune('0'+usage)), 1)
		h, err := zone.ParseTLSA(nil, v)
		if err != nil {
			t.Fatalf("ParseTLSA(usage=%d): %v", usage, err)
		}
		if int(h.Usage) != usage {
			t.Errorf("Usage = %d, want %d", h.Usage, usage)
		}
	}
}

func TestParseTLSA_FullCertificate(t *testing.T) {
	// matching_type = 0 (Full) — RDATA carries the entire certificate;
	// length can far exceed a single digest.
	longHex := strings.Repeat("aa", 128)
	h, err := zone.ParseTLSA(nil, "3 0 0 "+longHex)
	if err != nil {
		t.Fatalf("ParseTLSA: %v", err)
	}
	if h.MatchingType != 0 {
		t.Errorf("MatchingType = %d, want 0 (Full)", h.MatchingType)
	}
	if got := len(h.CertificateAssociationData); got != 128 {
		t.Errorf("data length = %d, want 128", got)
	}
}

// SMIMEA shares the TLSA struct and parser. The factory in
// handlers.go is wired via [zone.RegisterHandlers]; here we go through
// the public registry to assert the registration actually dispatches.

const smimeaHex = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
const smimeaValue = "3 1 1 " + smimeaHex

func TestRegisterHandlers_DispatchesSMIMEAToTLSA(t *testing.T) {
	rr := newRR(t, "abcdef._smimecert.example.com.", 3600, "IN", "SMIMEA", smimeaValue)
	h, ok := rr.Handler().(*zone.TLSA)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.TLSA (SMIMEA reuses the TLSA struct)", rr.Handler())
	}
	if h.Usage != 3 || h.Selector != 1 || h.MatchingType != 1 {
		t.Errorf("SMIMEA parsed header = {%d %d %d}, want {3 1 1}", h.Usage, h.Selector, h.MatchingType)
	}
	if got := hex.EncodeToString(h.CertificateAssociationData); got != smimeaHex {
		t.Errorf("data hex = %q, want %q", got, smimeaHex)
	}
}

func TestSMIMEA_MatchesTLSAWire(t *testing.T) {
	const v = "3 1 1 aabbccdd"
	tlsaRR := newRR(t, "_443._tcp.example.com.", 3600, "IN", "TLSA", v)
	smimeaRR := newRR(t, "hash._smimecert.example.com.", 3600, "IN", "SMIMEA", v)

	var tb, sb wire.Builder
	if err := tlsaRR.WireBody(&tb); err != nil {
		t.Fatalf("TLSA WireBody: %v", err)
	}
	if err := smimeaRR.WireBody(&sb); err != nil {
		t.Fatalf("SMIMEA WireBody: %v", err)
	}
	if !bytes.Equal(tb.Bytes(), sb.Bytes()) {
		t.Errorf("TLSA / SMIMEA wire bodies differ:\nTLSA   = %x\nSMIMEA = %x", tb.Bytes(), sb.Bytes())
	}
}

func TestZone_ReadString_TLSARecord(t *testing.T) {
	var z zone.Zone
	const text = `
$ORIGIN example.com.
$TTL 3600
_443._tcp  IN  TLSA  3 1 1 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("_443._tcp.example.com.", types.TypeTLSA)
	if rr == nil {
		t.Fatalf("TLSA record missing from zone")
	}
	h, ok := rr.Handler().(*zone.TLSA)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.TLSA", rr.Handler())
	}
	if h.Usage != 3 || h.Selector != 1 || h.MatchingType != 1 {
		t.Errorf("parsed header = {%d %d %d}, want {3 1 1}", h.Usage, h.Selector, h.MatchingType)
	}
}
