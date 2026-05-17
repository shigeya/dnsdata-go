package dnssec_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// signZone is a one-stop helper: build an ECDSA P-256 key, install it
// into a fresh dnssec.Zone, add a single A record, sign the A rrset
// and re-add the resulting RRSIG. Returns the assembled zone plus the
// key so tests can mutate them further.
func signZone(t *testing.T, label string) (*dnssec.Zone, *dnssec.DNSKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyData := encodeECDSAKeyData(t, &priv.PublicKey, 32)
	dnskeyValue := "257 3 13 " + base64.StdEncoding.EncodeToString(keyData)

	z := dnssec.NewZone()

	// DNSKEY record + handler.
	dnskeyRR, err := z.AddRRFromParts(label, 3600, "IN", "DNSKEY", dnskeyValue)
	if err != nil {
		t.Fatalf("AddRR(DNSKEY): %v", err)
	}
	key, ok := dnskeyRR.Handler().(*dnssec.DNSKey)
	if !ok {
		t.Fatalf("DNSKEY handler is %T, not *dnssec.DNSKey (did you forget RegisterHandlers?)", dnskeyRR.Handler())
	}
	key.SetPrivateKey(priv)

	// A record to sign.
	if _, err := z.AddRRFromParts("www."+label, 300, "IN", "A", "192.0.2.1"); err != nil {
		t.Fatalf("AddRR(A): %v", err)
	}

	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()
	rrsigRR, err := z.SignRR("www."+label, 300, types.TypeA, key, inception, expire)
	if err != nil {
		t.Fatalf("SignRR: %v", err)
	}
	if rrsigRR == nil {
		t.Fatal("SignRR returned nil RR")
	}
	z.AddRR(rrsigRR)

	return z, key
}

func TestZone_SignAndVerifyRRSet_RoundTrip(t *testing.T) {
	z, _ := signZone(t, "example.com.")

	ok, err := z.VerifyRRSet("www.example.com.", types.TypeA, dnssec.KeyModeNone, "")
	if err != nil {
		t.Fatalf("VerifyRRSet: %v", err)
	}
	if !ok {
		t.Errorf("VerifyRRSet returned false for self-signed RRset")
	}
}

func TestZone_VerifyRRSet_MissingSignatureFails(t *testing.T) {
	z := dnssec.NewZone()
	if _, err := z.AddRRFromParts("nosig.example.com.", 300, "IN", "A", "192.0.2.2"); err != nil {
		t.Fatalf("AddRR: %v", err)
	}
	ok, _ := z.VerifyRRSet("nosig.example.com.", types.TypeA, dnssec.KeyModeNone, "")
	if ok {
		t.Errorf("VerifyRRSet returned true for unsigned RRset")
	}
}

func TestZone_VerifyRRSet_TamperedAFails(t *testing.T) {
	z, _ := signZone(t, "tamper.example.")

	// Tamper: append a second A record after the signature was made.
	if _, err := z.AddRRFromParts("www.tamper.example.", 300, "IN", "A", "203.0.113.99"); err != nil {
		t.Fatalf("AddRR: %v", err)
	}

	ok, _ := z.VerifyRRSet("www.tamper.example.", types.TypeA, dnssec.KeyModeNone, "")
	if ok {
		t.Errorf("VerifyRRSet returned true after tampering with the RRset")
	}
}

func TestZone_FindDNSKey_ByKeyTag(t *testing.T) {
	z, key := signZone(t, "lookup.example.")

	got := z.FindDNSKey("lookup.example.", key.KeyTag)
	if got == nil {
		t.Fatalf("FindDNSKey returned nil")
	}
	if got.KeyTag != key.KeyTag {
		t.Errorf("KeyTag = %d, want %d", got.KeyTag, key.KeyTag)
	}

	if z.FindDNSKey("lookup.example.", 99) != nil {
		t.Errorf("FindDNSKey returned non-nil for unknown tag")
	}
}

func TestZone_AddSEP_AndIsSecureEntryPoint(t *testing.T) {
	z := dnssec.NewZone()
	if z.IsSecureEntryPoint(".") {
		t.Errorf("empty zone treats . as SEP")
	}
	z.AddSEP(".")
	if !z.IsSecureEntryPoint(".") {
		t.Errorf("AddSEP did not register .")
	}
}

func TestZone_VerifyDSRRSet_NoParentReturnsFalse(t *testing.T) {
	z := dnssec.NewZone()
	ok, err := z.VerifyDSRRSet("child.example.")
	if err != nil {
		t.Fatalf("VerifyDSRRSet: %v", err)
	}
	if ok {
		t.Errorf("VerifyDSRRSet returned true with no parent zone")
	}
}

func TestZone_CreateDigestTarget_NoRRset(t *testing.T) {
	z := dnssec.NewZone()
	rrsig := &dnssec.RRSig{
		TypeCovered: types.TypeA,
		Algorithm:   types.AlgoRSASHA256,
		Signer:      "example.",
	}
	target, err := z.CreateDigestTarget(rrsig, "missing.example.", types.TypeA)
	if err != nil {
		t.Fatalf("CreateDigestTarget: %v", err)
	}
	if target != nil {
		t.Errorf("expected nil target for missing RRset, got %d bytes", len(target))
	}
}
