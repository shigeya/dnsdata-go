package verifier_test

import (
	"context"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestValidate_Insecure_NoDS_NSECProof builds a two-level chain where
// com. exists and is signed, but example.com. has no DS — and com.
// proves it with an NSEC record whose bitmap has NS but neither DS nor
// SOA. The expected verdict is Insecure with InsecureAt = "example.com.".
func TestValidate_Insecure_NoDS_NSECProof(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)

	// com. publishes an NSEC at example.com. that asserts NS but no DS.
	// "f.com." is a placeholder NextDomain — any later label suffices
	// because no zone walking happens in this test.
	com.addSignedRR(t, "example.com.", 3600, types.TypeNSEC, "f.com. NS RRSIG NSEC", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     nsecProof(com.z, "example.com."),
		{"example.com.", types.TypeDNSKEY}: nil,
	}
	resolver := &mockResolver{responses: resp}
	v, err := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictInsecure {
		t.Errorf("Verdict = %s, want insecure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if res.InsecureAt != "example.com." {
		t.Errorf("InsecureAt = %q, want example.com.", res.InsecureAt)
	}
	if !strings.Contains(res.InsecureReason, "NSEC") {
		t.Errorf("InsecureReason = %q, want it to mention NSEC", res.InsecureReason)
	}
}

// TestValidate_Insecure_NoDS_NSEC3Proof is the NSEC3 analogue: com. has
// no DS for example.com. and proves it with an NSEC3 record whose
// owner hash matches H(example.com.) and whose bitmap has NS without
// DS / SOA.
func TestValidate_Insecure_NoDS_NSEC3Proof(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)

	const iterations = 0
	var salt []byte
	hash, err := dnssec.ComputeNSEC3Hash("example.com.", 1, iterations, salt)
	if err != nil {
		t.Fatalf("ComputeNSEC3Hash: %v", err)
	}
	owner := base32hexEncode(hash) + ".com."
	// NextHashedOwner: increment the last byte so the NSEC3 is a
	// degenerate "next is one past me" record.
	next := append([]byte(nil), hash...)
	next[len(next)-1]++
	nsec3RData := joinSpace("1", "0", "0", "-", base32hexEncode(next), "NS", "RRSIG", "NSEC3")
	com.addSignedRR(t, owner, 3600, types.TypeNSEC3, nsec3RData, inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     nsec3Proof(com.z, owner),
		{"example.com.", types.TypeDNSKEY}: nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictInsecure {
		t.Errorf("Verdict = %s, want insecure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if res.InsecureAt != "example.com." {
		t.Errorf("InsecureAt = %q, want example.com.", res.InsecureAt)
	}
	if !strings.Contains(res.InsecureReason, "NSEC3") {
		t.Errorf("InsecureReason = %q, want it to mention NSEC3", res.InsecureReason)
	}
}

// TestValidate_Insecure_NoDS_NSEC3_OptOut covers the looser NSEC3
// proof: example.com. is in a range covered by an opt-out NSEC3, not
// matched by one. RFC 5155 §6 considers this a valid no-DS proof.
func TestValidate_Insecure_NoDS_NSEC3_OptOut(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)

	const iterations = 0
	var salt []byte
	target, err := dnssec.ComputeNSEC3Hash("example.com.", 1, iterations, salt)
	if err != nil {
		t.Fatalf("ComputeNSEC3Hash: %v", err)
	}
	owner := make([]byte, len(target))
	copy(owner, target)
	if owner[0] == 0 {
		owner[0] = 1
	}
	owner[0]--
	next := make([]byte, len(target))
	copy(next, target)
	if next[0] == 0xff {
		next[0] = 0xfe
	}
	next[0]++
	ownerName := base32hexEncode(owner) + ".com."
	nsec3RData := joinSpace("1", "1", "0", "-", base32hexEncode(next), "NS", "RRSIG", "NSEC3")
	com.addSignedRR(t, ownerName, 3600, types.TypeNSEC3, nsec3RData, inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     nsec3Proof(com.z, ownerName),
		{"example.com.", types.TypeDNSKEY}: nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictInsecure {
		t.Errorf("Verdict = %s, want insecure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if !strings.Contains(res.InsecureReason, "opt-out") {
		t.Errorf("InsecureReason = %q, want it to mention opt-out", res.InsecureReason)
	}
}

// TestValidate_Bogus_NoDS_BogusBitmap ensures that a parent which
// returns *some* NSEC at the child name but with a bitmap that does
// not have the no-DS shape (e.g., DS bit is set, contradicting the
// missing DS rrset) does NOT classify the chain as Insecure. With no
// valid proof, the chain walker falls back to its previous behaviour
// and treats the level as a non-cut. Since example.com.'s DNSKEY then
// fails to resolve, the verdict surfaces as Indeterminate at the leaf
// — but crucially NOT Insecure.
func TestValidate_NoDS_WithoutValidProof_NotInsecure(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)

	// NSEC at example.com. claims a DS bit — proof is *not* a no-DS
	// proof.
	com.addSignedRR(t, "example.com.", 3600, types.TypeNSEC, "f.com. NS DS RRSIG NSEC", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     nsecProof(com.z, "example.com."),
		{"example.com.", types.TypeDNSKEY}: nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict == verifier.VerdictInsecure {
		t.Errorf("Verdict = insecure, but the NSEC bitmap claims DS — proof must NOT pass")
	}
}

// nsecProof returns the NSEC rrset at owner together with the RRSIG
// covering NSEC. The records still belong to z and are reused (the
// resolver fixture is read-only).
func nsecProof(z *dnssec.Zone, owner string) []*zone.ResourceRecord {
	return rrsetWithSigs(z, owner, types.TypeNSEC)
}

// nsec3Proof returns the NSEC3 rrset at owner together with the RRSIG
// covering NSEC3.
func nsec3Proof(z *dnssec.Zone, owner string) []*zone.ResourceRecord {
	return rrsetWithSigs(z, owner, types.TypeNSEC3)
}

// base32hexEncode encodes b in RFC 4648 §7 base32hex without padding
// — the form NSEC3 owner labels use.
func base32hexEncode(b []byte) string {
	return strings.TrimRight(base32.HexEncoding.EncodeToString(b), "=")
}
