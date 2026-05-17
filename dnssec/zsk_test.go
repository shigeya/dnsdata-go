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

// genECDSAKey builds an ECDSA-P256 private key and the matching
// `<flags> 3 13 <base64>` DNSKEY presentation value. flags chooses KSK
// (257) vs ZSK (256) semantics.
func genECDSAKey(t *testing.T, flags uint16) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyData := encodeECDSAKeyData(t, &priv.PublicKey, 32)
	value := dec(flags) + " 3 13 " + base64.StdEncoding.EncodeToString(keyData)
	return priv, value
}

// TestVerify_ZSKMode_ChainsThroughKSK exercises the KeyModeZSK path:
// the A rrset is signed by a non-SEP ZSK; verifyZSK is invoked, which
// recursively validates the DNSKEY rrset (signed by an in-zone KSK)
// against the configured SEP.
func TestVerify_ZSKMode_ChainsThroughKSK(t *testing.T) {
	apex := "zsk.example."

	kskPriv, kskValue := genECDSAKey(t, 257)
	zskPriv, zskValue := genECDSAKey(t, 256)

	z := dnssec.NewZone()

	kskRR, err := z.AddRRFromParts(apex, 3600, "IN", "DNSKEY", kskValue)
	if err != nil {
		t.Fatalf("AddRR(KSK): %v", err)
	}
	zskRR, err := z.AddRRFromParts(apex, 3600, "IN", "DNSKEY", zskValue)
	if err != nil {
		t.Fatalf("AddRR(ZSK): %v", err)
	}
	ksk := kskRR.Handler().(*dnssec.DNSKey)
	zsk := zskRR.Handler().(*dnssec.DNSKey)
	ksk.SetPrivateKey(kskPriv)
	zsk.SetPrivateKey(zskPriv)

	if !ksk.IsSecureEntryPoint() {
		t.Fatalf("KSK should have SEP flag, flags=%d", ksk.Flags)
	}
	if zsk.IsSecureEntryPoint() {
		t.Fatalf("ZSK should NOT have SEP flag, flags=%d", zsk.Flags)
	}

	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	// KSK signs the DNSKEY rrset (both keys).
	dnskeyRRSig, err := z.SignRR(apex, 3600, types.TypeDNSKEY, ksk, inception, expire)
	if err != nil || dnskeyRRSig == nil {
		t.Fatalf("SignRR(DNSKEY): %v", err)
	}
	z.AddRR(dnskeyRRSig)

	// ZSK signs the A rrset.
	if _, err := z.AddRRFromParts("www."+apex, 300, "IN", "A", "192.0.2.40"); err != nil {
		t.Fatalf("AddRR(A): %v", err)
	}
	aRRSig, err := z.SignRR("www."+apex, 300, types.TypeA, zsk, inception, expire)
	if err != nil || aRRSig == nil {
		t.Fatalf("SignRR(A): %v", err)
	}
	z.AddRR(aRRSig)

	// Trust the KSK via SEP set.
	z.AddSEP(apex)

	ok, err := z.VerifyRRSet("www."+apex, types.TypeA, dnssec.KeyModeZSK, "")
	if err != nil {
		t.Fatalf("VerifyRRSet(ZSK): %v", err)
	}
	if !ok {
		t.Errorf("KeyModeZSK verification of A rrset returned false")
	}
}
