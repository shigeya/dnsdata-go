package dnssec_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Sample DNSKEY (RSA/SHA-1, KSK with flags=257) borrowed from
// dnsdata-js's dnssec_rr.spec.ts so the two implementations remain
// behaviourally aligned.
const sampleDNSKEYValue = "257 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w=="

func newDNSKEYRR(t *testing.T, label, value string) *zone.ResourceRecord {
	t.Helper()
	rr, err := zone.NewResourceRecord(label, 3600, "IN", "DNSKEY", value)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord(DNSKEY): %v", err)
	}
	return rr
}

func TestParseDNSKey_PresentationFormat(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)
	k, err := dnssec.ParseDNSKey(rr, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	if k.Flags != 257 {
		t.Errorf("Flags = %d, want 257", k.Flags)
	}
	if k.Protocol != 3 {
		t.Errorf("Protocol = %d, want 3", k.Protocol)
	}
	if k.Algorithm != types.AlgoRSASHA1 {
		t.Errorf("Algorithm = %d, want %d", k.Algorithm, types.AlgoRSASHA1)
	}
	if len(k.KeyData) == 0 {
		t.Errorf("KeyData empty")
	}
}

func TestParseDNSKey_Malformed(t *testing.T) {
	_, err := dnssec.ParseDNSKey(nil, "this is not a DNSKEY")
	if !errors.Is(err, dnssec.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestDNSKey_KeyTagBetween1And65535(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)
	k, err := dnssec.ParseDNSKey(rr, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	if k.KeyTag == 0 {
		t.Errorf("KeyTag = 0, want positive")
	}
}

// RFC 4034 Appendix B.1: for algorithm 1 (RSAMD5), KeyTag is the low 16
// bits of the key modulus — i.e. the last two bytes of KeyData.
func TestDNSKey_KeyTag_RSAMD5(t *testing.T) {
	keyData := []byte{0x01, 0x02, 0x03, 0xAB, 0xCD}
	rr, _ := zone.NewResourceRecord("example.com.", 3600, "IN", "DNSKEY", "257 3 1 AQID")
	k := dnssec.NewDNSKey(rr, 257, 3, types.AlgoRSAMD5, keyData)
	if k.KeyTag != 0xABCD {
		t.Errorf("KeyTag = 0x%04x, want 0xABCD", k.KeyTag)
	}
}

func TestDNSKey_KSKvsZSK(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)

	ksk, err := dnssec.ParseDNSKey(rr, "257 3 5 AQID")
	if err != nil {
		t.Fatalf("ParseDNSKey(KSK): %v", err)
	}
	if !ksk.IsZoneKey() {
		t.Errorf("KSK should be a zone key")
	}
	if !ksk.IsSecureEntryPoint() {
		t.Errorf("KSK should be a secure entry point")
	}

	zsk, err := dnssec.ParseDNSKey(rr, "256 3 5 AQID")
	if err != nil {
		t.Fatalf("ParseDNSKey(ZSK): %v", err)
	}
	if !zsk.IsZoneKey() {
		t.Errorf("ZSK should be a zone key")
	}
	if zsk.IsSecureEntryPoint() {
		t.Errorf("ZSK should NOT be a secure entry point")
	}
}

func TestDNSKey_WireBody(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)
	k, err := dnssec.ParseDNSKey(rr, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	var b wire.Builder
	if err := k.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()

	// rdlen(2) + flags(2) + protocol(1) + algorithm(1) + key_data
	want := 2 + 4 + len(k.KeyData)
	if len(out) != want {
		t.Errorf("WireBody length = %d, want %d", len(out), want)
	}
	// Flags 257 = 0x0101
	if out[2] != 0x01 || out[3] != 0x01 {
		t.Errorf("flags wire bytes = 0x%02x%02x, want 0x0101", out[2], out[3])
	}
	if out[4] != 3 {
		t.Errorf("protocol byte = %d, want 3", out[4])
	}
	if out[5] != 5 {
		t.Errorf("algorithm byte = %d, want 5", out[5])
	}
}

func TestDNSKey_DSDigestData(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)
	k, err := dnssec.ParseDNSKey(rr, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	data, err := k.DSDigestData()
	if err != nil {
		t.Fatalf("DSDigestData: %v", err)
	}
	// Should begin with the wire-form owner name: \x07example\x03net\x00.
	if data[0] != 7 {
		t.Errorf("first byte = %d, want 7 (length of 'example')", data[0])
	}
	if len(data) <= 12+len(k.KeyData) {
		t.Errorf("DSDigestData length %d looks too short", len(data))
	}
}

func TestDNSKey_PublicKey_RSA(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)
	k, err := dnssec.ParseDNSKey(rr, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	if _, err := k.PublicKey(); err != nil {
		t.Errorf("PublicKey: %v", err)
	}
}

func TestDNSKey_ISCKeyBaseFilename(t *testing.T) {
	rr := newDNSKEYRR(t, "example.net.", sampleDNSKEYValue)
	k, err := dnssec.ParseDNSKey(rr, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	fn := k.ISCKeyBaseFilename()
	want := regexp.MustCompile(`^Kexample\.net\.\+005\+\d{5}$`)
	if !want.MatchString(fn) {
		t.Errorf("filename %q does not match %v", fn, want)
	}
}

// ECDSA P-256 round-trip: generate key, build a DNSKEY with raw x||y
// coordinates, set the matching private key, sign and verify a payload.
func TestDNSKey_ECDSA_P256_SignVerifyRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyData := encodeECDSAKeyData(t, &priv.PublicKey, 32)
	keyB64 := base64.StdEncoding.EncodeToString(keyData)
	value := "257 3 13 " + keyB64

	rr := newDNSKEYRR(t, "example.com.", value)
	k, err := dnssec.ParseDNSKey(rr, value)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	if k.Algorithm != types.AlgoECDSAP256SHA256 {
		t.Errorf("Algorithm = %d, want 13", k.Algorithm)
	}
	if len(k.KeyData) != 64 {
		t.Errorf("KeyData length = %d, want 64", len(k.KeyData))
	}

	k.SetPrivateKey(priv)
	payload := []byte{1, 2, 3, 4, 5}
	sig, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64 (r||s on P-256)", len(sig))
	}
	ok, err := k.Verify(payload, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("Verify returned false for valid signature")
	}

	// Tampered payload should be rejected.
	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 1
	bad, err := k.Verify(tampered, sig)
	if err != nil {
		t.Fatalf("Verify(tampered): %v", err)
	}
	if bad {
		t.Errorf("Verify returned true for tampered payload")
	}
}

func TestDNSKey_Ed25519_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(pub)
	value := "257 3 15 " + keyB64

	rr := newDNSKEYRR(t, "example.com.", value)
	k, err := dnssec.ParseDNSKey(rr, value)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	if k.Algorithm != types.AlgoED25519 {
		t.Errorf("Algorithm = %d, want 15", k.Algorithm)
	}
	if len(k.KeyData) != ed25519.PublicKeySize {
		t.Errorf("KeyData length = %d, want %d", len(k.KeyData), ed25519.PublicKeySize)
	}

	k.SetPrivateKey(priv)
	payload := []byte{1, 2, 3, 4, 5}
	sig, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	ok, err := k.Verify(payload, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("Verify returned false for valid signature")
	}
}

// encodeECDSAKeyData packs an ECDSA public key into the raw x||y form
// expected by RFC 6605. Uses [ecdsa.PublicKey.ECDH] → [ecdh.PublicKey.Bytes]
// which returns the SEC1 uncompressed point `0x04 || x || y`; the
// leading byte is stripped before returning. coordLen is asserted as a
// sanity check.
func encodeECDSAKeyData(t *testing.T, pub *ecdsa.PublicKey, coordLen int) []byte {
	t.Helper()
	ek, err := pub.ECDH()
	if err != nil {
		t.Fatalf("ecdsa.PublicKey.ECDH: %v", err)
	}
	raw := ek.Bytes()
	if want := 1 + 2*coordLen; len(raw) != want {
		t.Fatalf("ECDH key bytes length = %d, want %d", len(raw), want)
	}
	if raw[0] != 0x04 {
		t.Fatalf("ECDH key prefix = 0x%02x, want 0x04 (uncompressed)", raw[0])
	}
	return raw[1:]
}
