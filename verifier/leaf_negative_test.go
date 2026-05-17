package verifier_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestValidate_SecureNoData_NSEC builds a chain where example.com.
// exists and is signed, www.example.com. exists with an A record, but
// the qtype asked for (AAAA) is missing. The leaf zone serves a
// matching NSEC at www.example.com. whose bitmap covers A and RRSIG
// but not AAAA — that is the NODATA proof. Expected verdict:
// secure-nodata.
func TestValidate_SecureNoData_NSEC(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	// www.example.com. has A and an NSEC asserting "I have A and
	// RRSIG, nothing else." Next domain is irrelevant for matching
	// denial.
	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeA, "192.0.2.1", inception, expire)
	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeNSEC, "z.example.com. A RRSIG NSEC", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:               rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:            rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:        rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:    rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeAAAA}:  rrsetWithSigs(leaf.z, "www.example.com.", types.TypeNSEC),
		{"www.example.com.", types.TypeDS}:    nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeAAAA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecureNoData {
		t.Errorf("Verdict = %s, want secure-nodata", res.Verdict)
	}
	if !strings.Contains(res.NegativeReason, "NSEC") {
		t.Errorf("NegativeReason = %q, want NSEC mention", res.NegativeReason)
	}
}

// TestValidate_SecureNXDomain_NSEC: qname missing.example.com. has no
// records, and the leaf zone produces (a) an NSEC covering
// missing.example.com. and (b) an NSEC covering *.example.com.
// (no wildcard exists). Expected verdict: secure-nxdomain.
func TestValidate_SecureNXDomain_NSEC(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	// One NSEC at example.com. apex covers names from "example.com."
	// up to "n.example.com." — including missing.example.com. and
	// *.example.com. (since * sorts canonically before any other
	// label in NSEC ordering? actually \052 = 0x2A sorts as a
	// regular octet so *.example.com. > example.com. but ordering
	// depends on next domain).
	//
	// Easier: two NSECs.
	//   apex NSEC: example.com. → m.example.com.   (covers *.example.com.)
	//   covering: m.example.com. → z.example.com.   (covers missing.example.com.)
	leaf.addSignedRR(t, "example.com.", 300, types.TypeNSEC, "m.example.com. NS SOA RRSIG NSEC", inception, expire)
	leaf.addSignedRR(t, "m.example.com.", 300, types.TypeNSEC, "z.example.com. A RRSIG NSEC", inception, expire)

	// Resolver returns both NSECs when asked for missing.example.com..
	nsecs := append(
		[]*zone.ResourceRecord{},
		rrsetWithSigs(leaf.z, "example.com.", types.TypeNSEC)...,
	)
	nsecs = append(nsecs, rrsetWithSigs(leaf.z, "m.example.com.", types.TypeNSEC)...)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:                rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                 rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:             rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:         rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:     rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"missing.example.com.", types.TypeA}:  nsecs,
		{"missing.example.com.", types.TypeDS}: nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "missing.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecureNXDomain {
		t.Errorf("Verdict = %s, want secure-nxdomain (negative reason=%q)", res.Verdict, res.NegativeReason)
	}
	if !strings.Contains(res.NegativeReason, "wildcard") {
		t.Errorf("NegativeReason = %q, want wildcard mention", res.NegativeReason)
	}
}

// TestValidate_SecureNoData_NSEC3: NODATA via an NSEC3 whose owner
// hash equals H(www.example.com.) and whose bitmap excludes AAAA.
func TestValidate_SecureNoData_NSEC3(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	const iterations = 0
	var salt []byte
	target, err := dnssec.ComputeNSEC3Hash("www.example.com.", 1, iterations, salt)
	if err != nil {
		t.Fatalf("ComputeNSEC3Hash: %v", err)
	}
	next := make([]byte, len(target))
	copy(next, target)
	next[len(next)-1]++
	ownerName := base32hexEncode(target) + ".example.com."
	nsec3RData := joinSpace("1", "0", "0", "-", base32hexEncode(next), "A", "RRSIG", "NSEC3")
	leaf.addSignedRR(t, ownerName, 3600, types.TypeNSEC3, nsec3RData, inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:               rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:            rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:        rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:    rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeAAAA}:  rrsetWithSigs(leaf.z, ownerName, types.TypeNSEC3),
		{"www.example.com.", types.TypeDS}:    nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeAAAA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecureNoData {
		t.Errorf("Verdict = %s, want secure-nodata (reason=%q)", res.Verdict, res.NegativeReason)
	}
}

// TestValidate_SecureNXDomain_NSEC3 exercises the RFC 5155 §8.4
// three-NSEC3 closest-encloser proof: a matching NSEC3 at the closest
// encloser (example.com.), a covering NSEC3 for the next-closer
// (missing.example.com.), and a covering NSEC3 for the wildcard
// (*.example.com.).
func TestValidate_SecureNXDomain_NSEC3(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	const iters = 0
	var salt []byte
	hashOf := func(name string) []byte {
		h, err := dnssec.ComputeNSEC3Hash(name, 1, iters, salt)
		if err != nil {
			t.Fatalf("hash %s: %v", name, err)
		}
		return h
	}

	hCE := hashOf("example.com.")
	hNC := hashOf("missing.example.com.")
	hWC := hashOf("*.example.com.")

	// Sentinels: NSEC3 #1 matches CE; NSEC3 #2 covers NC; NSEC3 #3
	// covers WC. To make a "covers" record cheap we choose owners
	// one byte below the target and next-hashed-owners one byte
	// above.
	makeCover := func(hash []byte) (owner []byte, next []byte) {
		owner = append([]byte(nil), hash...)
		next = append([]byte(nil), hash...)
		// owner just below hash, next just above.
		owner[len(owner)-1]--
		next[len(next)-1]++
		return
	}

	// Matching CE: owner is exactly the CE hash, next is anything.
	ceOwnerName := base32hexEncode(hCE) + ".example.com."
	ceNext := append([]byte(nil), hCE...)
	ceNext[len(ceNext)-1]++
	leaf.addSignedRR(t, ceOwnerName, 3600, types.TypeNSEC3,
		joinSpace("1", "0", "0", "-", base32hexEncode(ceNext), "NS", "SOA", "RRSIG", "DNSKEY", "NSEC3PARAM"),
		inception, expire)

	// Covering NC: owner < hNC, next > hNC.
	ncOwner, ncNext := makeCover(hNC)
	ncOwnerName := base32hexEncode(ncOwner) + ".example.com."
	leaf.addSignedRR(t, ncOwnerName, 3600, types.TypeNSEC3,
		joinSpace("1", "0", "0", "-", base32hexEncode(ncNext), "RRSIG", "NSEC3"),
		inception, expire)

	// Covering WC: owner < hWC, next > hWC.
	wcOwner, wcNext := makeCover(hWC)
	wcOwnerName := base32hexEncode(wcOwner) + ".example.com."
	leaf.addSignedRR(t, wcOwnerName, 3600, types.TypeNSEC3,
		joinSpace("1", "0", "0", "-", base32hexEncode(wcNext), "RRSIG", "NSEC3"),
		inception, expire)

	// Bundle all three NSEC3s into the resolver response for the
	// NXDOMAIN query.
	var nsec3s []*zone.ResourceRecord
	for _, owner := range []string{ceOwnerName, ncOwnerName, wcOwnerName} {
		nsec3s = append(nsec3s, rrsetWithSigs(leaf.z, owner, types.TypeNSEC3)...)
	}

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:                rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                 rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:             rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:         rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:     rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"missing.example.com.", types.TypeA}:  nsec3s,
		{"missing.example.com.", types.TypeDS}: nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "missing.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecureNXDomain {
		t.Errorf("Verdict = %s, want secure-nxdomain (negative reason=%q)", res.Verdict, res.NegativeReason)
	}
	if !strings.Contains(res.NegativeReason, "wildcard") {
		t.Errorf("NegativeReason = %q, want wildcard mention", res.NegativeReason)
	}
}

// TestValidate_Indeterminate_NoProof: leaf returns no records and no
// negative proof. Verdict stays Indeterminate (was the v0.1.0 default
// for "no rrset / no proof").
func TestValidate_Indeterminate_NoProof(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:               rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:            rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:        rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:    rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeAAAA}:  nil,
		{"www.example.com.", types.TypeDS}:    nil,
	}
	resolver := &mockResolver{responses: resp}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeAAAA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictIndeterminate {
		t.Errorf("Verdict = %s, want indeterminate (no proof should NOT be promoted)", res.Verdict)
	}
}

// TestVerdict_NegativeJSONRoundTrip exercises the JSON marshaller for
// the new verdict states.
func TestVerdict_NegativeJSONRoundTrip(t *testing.T) {
	for _, v := range []verifier.Verdict{
		verifier.VerdictSecureNoData,
		verifier.VerdictSecureNXDomain,
	} {
		b, err := v.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON(%s): %v", v, err)
		}
		var got verifier.Verdict
		if err := got.UnmarshalJSON(b); err != nil {
			t.Fatalf("UnmarshalJSON: %v", err)
		}
		if got != v {
			t.Errorf("round-trip: got %s, want %s", got, v)
		}
	}
}
