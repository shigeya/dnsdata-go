package dnssec_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// signedZone is the test fixture used by the chain tests: a single
// DNSSEC zone (acting as both KSK and ZSK / CSK style) with one signed
// A record and a self-signed DNSKEY rrset.
type signedZone struct {
	z   *dnssec.Zone
	key *dnssec.DNSKey
}

// buildSignedZone produces a zone signed end-to-end: the DNSKEY rrset
// at `apex` is self-signed by `key`, and a single A record at
// `aLabel` is signed by the same key. Inception/expire are set to a
// generous window around `now`.
func buildSignedZone(t *testing.T, apex, aLabel string, ip string) signedZone {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyData := encodeECDSAKeyData(t, &priv.PublicKey, 32)
	dnskeyValue := "257 3 13 " + base64.StdEncoding.EncodeToString(keyData) // flag 257 = KSK/SEP

	z := dnssec.NewZone()
	dnskeyRR, err := z.AddRRFromParts(apex, 3600, "IN", "DNSKEY", dnskeyValue)
	if err != nil {
		t.Fatalf("AddRR(DNSKEY): %v", err)
	}
	key := dnskeyRR.Handler().(*dnssec.DNSKey)
	key.SetPrivateKey(priv)

	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	// Self-sign the DNSKEY rrset.
	dnskeyRRSig, err := z.SignRR(apex, 3600, types.TypeDNSKEY, key, inception, expire)
	if err != nil || dnskeyRRSig == nil {
		t.Fatalf("SignRR(DNSKEY): %v", err)
	}
	z.AddRR(dnskeyRRSig)

	// Sign the A rrset.
	if _, err := z.AddRRFromParts(aLabel, 300, "IN", "A", ip); err != nil {
		t.Fatalf("AddRR(A): %v", err)
	}
	aRRSig, err := z.SignRR(aLabel, 300, types.TypeA, key, inception, expire)
	if err != nil || aRRSig == nil {
		t.Fatalf("SignRR(A): %v", err)
	}
	z.AddRR(aRRSig)

	return signedZone{z: z, key: key}
}

// TestChain_SEPAccepted exercises verifyDelegationSigner's short-circuit
// path: if the DNSKEY's owner is in the SEP set, KSK validation
// succeeds without any DS lookup.
func TestChain_SEPAccepted(t *testing.T) {
	sz := buildSignedZone(t, "example.", "www.example.", "192.0.2.10")
	sz.z.AddSEP("example.")

	ok, err := sz.z.VerifyRRSet("www.example.", types.TypeA, dnssec.KeyModeNone, "")
	if err != nil {
		t.Fatalf("VerifyRRSet(A): %v", err)
	}
	if !ok {
		t.Errorf("VerifyRRSet returned false for SEP-trusted chain")
	}

	// KSK mode on the DNSKEY rrset must also succeed because the apex
	// is configured as a SEP.
	ok, err = sz.z.VerifyRRSet("example.", types.TypeDNSKEY, dnssec.KeyModeKSK, "")
	if err != nil {
		t.Fatalf("VerifyRRSet(DNSKEY, KSK): %v", err)
	}
	if !ok {
		t.Errorf("KSK-mode DNSKEY verification failed with SEP configured")
	}
}

// TestChain_ParentDS exercises verifyDelegationSigner against a real
// parent zone: build a parent zone holding a DS rrset for the child,
// then verify the child's KSK rolls up to the parent via DS digest.
func TestChain_ParentDS(t *testing.T) {
	child := buildSignedZone(t, "child.example.", "www.child.example.", "192.0.2.20")

	// Compute the DS digest of the child's KSK.
	dsInput, err := child.key.DSDigestData()
	if err != nil {
		t.Fatalf("DSDigestData: %v", err)
	}
	sum := sha256.Sum256(dsInput)
	dsValue := joinSpace(
		dec(child.key.KeyTag),
		dec(uint16(child.key.Algorithm)),
		"2",
		hex.EncodeToString(sum[:]),
	)

	// Parent zone holds the DS rrset (and we mark parent as a SEP so
	// the DS lookup terminates).
	parent := dnssec.NewZone()
	parent.AddSEP("example.")
	if _, err := parent.AddRRFromParts("child.example.", 3600, "IN", "DS", dsValue); err != nil {
		t.Fatalf("AddRR(DS): %v", err)
	}
	child.z.SetParent(parent)

	// KSK-mode verify of the child's DNSKEY rrset now walks up to
	// parent.DS, which authenticates the KSK.
	ok, err := child.z.VerifyRRSet("child.example.", types.TypeDNSKEY, dnssec.KeyModeKSK, "")
	if err != nil {
		t.Fatalf("VerifyRRSet(DNSKEY, KSK): %v", err)
	}
	if !ok {
		t.Errorf("KSK validation via parent DS failed")
	}

	if parent != child.z.Parent() {
		t.Errorf("Parent() did not return the configured parent zone")
	}
}

func TestChain_VerifyRRSet_KSKMode_ANotInDNSKEYShortCircuit(t *testing.T) {
	// KSK-mode verification of an A rrset must NOT short-circuit on
	// the DNSKEY-only branch; the signature itself must be checked.
	sz := buildSignedZone(t, "ksk.example.", "www.ksk.example.", "192.0.2.30")
	sz.z.AddSEP("ksk.example.")

	ok, err := sz.z.VerifyRRSet("www.ksk.example.", types.TypeA, dnssec.KeyModeKSK, "")
	if err != nil {
		t.Fatalf("VerifyRRSet: %v", err)
	}
	if !ok {
		t.Errorf("KSK-mode verification of A rrset returned false")
	}
}

// dec returns a decimal string for a small unsigned integer without
// dragging strconv/fmt into the imports list. Used by the DS value
// assembler above.
func dec(v uint16) string { return toString(v) }

// joinSpace concatenates s with single spaces between, without using
// strings.Join (also tested elsewhere).
func joinSpace(parts ...string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out = out + " " + p
	}
	return out
}
