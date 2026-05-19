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

// Ported from dnsdata-js/packages/core/tests/zone/rr/sshfp_rr.spec.ts.

const (
	sshfpSHA1Hex = "123456789abcdef67890123456789abcdef67890"
	sshfpValue   = "1 1 " + sshfpSHA1Hex // RSA / SHA-1
)

func TestParseSSHFP_PresentationFormat(t *testing.T) {
	rr := newRR(t, "host.example.com.", 3600, "IN", "SSHFP", sshfpValue)
	h, err := zone.ParseSSHFP(rr, sshfpValue)
	if err != nil {
		t.Fatalf("ParseSSHFP: %v", err)
	}
	if h.Algorithm != 1 {
		t.Errorf("Algorithm = %d, want 1 (RSA)", h.Algorithm)
	}
	if h.FPType != 1 {
		t.Errorf("FPType = %d, want 1 (SHA-1)", h.FPType)
	}
	if got := hex.EncodeToString(h.Fingerprint); got != sshfpSHA1Hex {
		t.Errorf("Fingerprint hex = %q, want %q", got, sshfpSHA1Hex)
	}
}

func TestParseSSHFP_Malformed(t *testing.T) {
	_, err := zone.ParseSSHFP(nil, "invalid")
	if !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestParseSSHFP_AcceptsWhitespaceInFingerprint(t *testing.T) {
	h, err := zone.ParseSSHFP(nil, "1 1 aabb ccdd eeff")
	if err != nil {
		t.Fatalf("ParseSSHFP: %v", err)
	}
	if got := hex.EncodeToString(h.Fingerprint); got != "aabbccddeeff" {
		t.Errorf("hex = %q, want aabbccddeeff", got)
	}
}

func TestSSHFP_WireBody(t *testing.T) {
	rr := newRR(t, "host.example.com.", 3600, "IN", "SSHFP", sshfpValue)
	h, err := zone.ParseSSHFP(rr, sshfpValue)
	if err != nil {
		t.Fatalf("ParseSSHFP: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	fpLen := len(sshfpSHA1Hex) / 2
	// rdlen(2) + algorithm(1) + fpType(1) + fingerprint (20 bytes for SHA-1)
	if want := 2 + 2 + fpLen; len(out) != want {
		t.Errorf("WireBody length = %d, want %d", len(out), want)
	}
	if rdlen := int(out[0])<<8 | int(out[1]); rdlen != 2+fpLen {
		t.Errorf("rdlen = %d, want %d", rdlen, 2+fpLen)
	}
	if out[2] != 1 {
		t.Errorf("algorithm = %d, want 1 (RSA)", out[2])
	}
	if out[3] != 1 {
		t.Errorf("fpType = %d, want 1 (SHA-1)", out[3])
	}
}

// SHA-256 fingerprint per RFC 6594 §2.2: 32 bytes regardless of algorithm.
func TestParseSSHFP_SHA256Fingerprint(t *testing.T) {
	sha256hex := strings.Repeat("aa", 32)
	h, err := zone.ParseSSHFP(nil, "3 2 "+sha256hex) // ECDSA / SHA-256
	if err != nil {
		t.Fatalf("ParseSSHFP: %v", err)
	}
	if h.Algorithm != 3 {
		t.Errorf("Algorithm = %d, want 3 (ECDSA)", h.Algorithm)
	}
	if h.FPType != 2 {
		t.Errorf("FPType = %d, want 2 (SHA-256)", h.FPType)
	}
	if got := len(h.Fingerprint); got != 32 {
		t.Errorf("Fingerprint length = %d, want 32", got)
	}
}

// Ed25519 (RFC 7479) — algorithm code 4.
func TestParseSSHFP_Ed25519(t *testing.T) {
	sha256hex := strings.Repeat("bb", 32)
	h, err := zone.ParseSSHFP(nil, "4 2 "+sha256hex)
	if err != nil {
		t.Fatalf("ParseSSHFP: %v", err)
	}
	if h.Algorithm != 4 {
		t.Errorf("Algorithm = %d, want 4 (Ed25519)", h.Algorithm)
	}
	if h.FPType != 2 {
		t.Errorf("FPType = %d, want 2 (SHA-256)", h.FPType)
	}
}

func TestSSHFP_Clone(t *testing.T) {
	rr := newRR(t, "host.example.com.", 3600, "IN", "SSHFP", sshfpValue)
	h, err := zone.ParseSSHFP(rr, sshfpValue)
	if err != nil {
		t.Fatalf("ParseSSHFP: %v", err)
	}
	cloned, ok := h.Clone().(*zone.SSHFP)
	if !ok {
		t.Fatalf("Clone returned %T, want *zone.SSHFP", h.Clone())
	}
	if cloned.Algorithm != h.Algorithm || cloned.FPType != h.FPType {
		t.Errorf("clone header mismatch: got {%d %d}, want {%d %d}",
			cloned.Algorithm, cloned.FPType, h.Algorithm, h.FPType)
	}
	if !bytes.Equal(cloned.Fingerprint, h.Fingerprint) {
		t.Errorf("Fingerprint mismatch after clone")
	}
	if len(cloned.Fingerprint) > 0 {
		cloned.Fingerprint[0] ^= 0xff
		if cloned.Fingerprint[0] == h.Fingerprint[0] {
			t.Errorf("Clone is not a deep copy: fingerprint backs the same slice")
		}
	}
}

func TestRegisterHandlers_DispatchesSSHFP(t *testing.T) {
	rr := newRR(t, "host.example.com.", 3600, "IN", "SSHFP", sshfpValue)
	h, ok := rr.Handler().(*zone.SSHFP)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.SSHFP", rr.Handler())
	}
	if h.Algorithm != 1 || h.FPType != 1 {
		t.Errorf("parsed header = {%d %d}, want {1 1}", h.Algorithm, h.FPType)
	}
}

func TestZone_ReadString_SSHFPRecord(t *testing.T) {
	var z zone.Zone
	const text = `
$ORIGIN example.com.
$TTL 3600
host  IN  SSHFP  1 1 123456789abcdef67890123456789abcdef67890
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("host.example.com.", types.TypeSSHFP)
	if rr == nil {
		t.Fatalf("SSHFP record missing from zone")
	}
	h, ok := rr.Handler().(*zone.SSHFP)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.SSHFP", rr.Handler())
	}
	if h.Algorithm != 1 || h.FPType != 1 {
		t.Errorf("parsed header = {%d %d}, want {1 1}", h.Algorithm, h.FPType)
	}
}
