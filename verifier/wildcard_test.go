package verifier_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// addWildcardSynthesisedRR places a synthesised rrset at synthName
// in s.z. The synthesis emulates an authoritative server that
// expanded a wildcard `*.<closestEncloser>` to synthName: the RR
// itself appears at synthName but its RRSIG.Labels says only the
// closest-encloser labels were originally signed, which is how
// validators detect wildcard expansion (RFC 4034 §3.1.3 +
// RFC 4035 §5.3.2).
//
// labelsOverride must equal the label count of the closest encloser
// (i.e. the wildcard owner minus the leading "*."). For
// `*.example.com.` that is 2.
func addWildcardSynthesisedRR(t *testing.T, s *signedZone, synthName string, ttl uint32, qtype uint16, value string, inception, expire int64, labelsOverride uint8) {
	t.Helper()

	typeName, err := types.RRTypeToString(qtype)
	if err != nil {
		t.Fatalf("RRTypeToString(%d): %v", qtype, err)
	}
	if _, err := s.z.AddRRFromParts(synthName, ttl, "IN", typeName, value); err != nil {
		t.Fatalf("AddRR %s/%s: %v", synthName, typeName, err)
	}

	// Construct an RRSIG with the wildcard's true Labels count. The
	// dnssec package's CreateDigestTarget reads Labels and rebuilds
	// the wildcard owner for digest computation when
	// Labels < LabelCount(synthName), so signing here with the
	// overridden Labels produces a digest target identical to what a
	// real signer would have produced at `*.<closestEncloser>`.
	rrsig := dnssec.NewRRSig(nil, synthName, ttl, qtype, inception, expire, s.key)
	rrsig.Labels = labelsOverride

	digestTarget, err := s.z.CreateDigestTarget(rrsig, synthName, qtype)
	if err != nil {
		t.Fatalf("CreateDigestTarget: %v", err)
	}
	if digestTarget == nil {
		t.Fatalf("CreateDigestTarget returned nil for %s/%s", synthName, typeName)
	}
	signature, err := s.key.Sign(digestTarget)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(signature)
	sigValue := fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
		typeName, s.key.Algorithm, rrsig.Labels, ttl, expire, inception,
		s.key.KeyTag, s.key.Label(), sigB64)
	rrsigRR, err := zone.NewResourceRecord(synthName, ttl, "IN", "RRSIG", sigValue)
	if err != nil {
		t.Fatalf("RRSIG NewResourceRecord: %v", err)
	}
	s.z.AddRR(rrsigRR)
}

// TestValidate_Wildcard_Secure: response for foo.example.com./A is a
// wildcard synthesis (RRSIG.Labels=2 over the qname's 3 labels), plus
// an NSEC covering foo.example.com.. Expected verdict: Secure with
// Result.Wildcard populated.
func TestValidate_Wildcard_Secure(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	// Wildcard synthesis: foo.example.com./A signed as if at
	// *.example.com. (Labels=2).
	addWildcardSynthesisedRR(t, leaf, "foo.example.com.", 300, types.TypeA, "192.0.2.99", inception, expire, 2)
	// NSEC covering foo.example.com. — owner < foo, next > foo.
	leaf.addSignedRR(t, "example.com.", 300, types.TypeNSEC, "z.example.com. NS SOA RRSIG NSEC", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:                rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                 rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:             rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:         rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:     rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		// Real DNS returns the synthesised A + its RRSIG + the NSEC
		// proving non-existence. Bundle all three.
		{"foo.example.com.", types.TypeA}: append(
			rrsetWithSigs(leaf.z, "foo.example.com.", types.TypeA),
			rrsetWithSigs(leaf.z, "example.com.", types.TypeNSEC)...,
		),
		{"foo.example.com.", types.TypeDS}: nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "foo.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Verdict = %s, want secure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if res.Wildcard == nil {
		t.Fatal("Wildcard is nil, want populated")
	}
	if res.Wildcard.Source != "*.example.com." {
		t.Errorf("Source = %q, want *.example.com.", res.Wildcard.Source)
	}
	if res.Wildcard.ClosestEncloser != "example.com." {
		t.Errorf("ClosestEncloser = %q, want example.com.", res.Wildcard.ClosestEncloser)
	}
	if res.Wildcard.NextCloser != "foo.example.com." {
		t.Errorf("NextCloser = %q, want foo.example.com.", res.Wildcard.NextCloser)
	}
	if res.Wildcard.ProofReason == "" {
		t.Errorf("ProofReason is empty")
	}
}

// TestValidate_Wildcard_MissingNonExistenceProof: same wildcard
// synthesis but the resolver omits the NSEC covering the next-closer
// name. Validator must classify as Bogus per RFC 4035 §5.3.4.
func TestValidate_Wildcard_MissingNonExistenceProof(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	addWildcardSynthesisedRR(t, leaf, "foo.example.com.", 300, types.TypeA, "192.0.2.99", inception, expire, 2)
	// No NSEC; resolver only returns the synthesised rrset.

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"foo.example.com.", types.TypeA}:  rrsetWithSigs(leaf.z, "foo.example.com.", types.TypeA),
		{"foo.example.com.", types.TypeDS}: nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "foo.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus (wildcard without next-closer proof)", res.Verdict)
	}
	if res.Wildcard != nil {
		t.Errorf("Wildcard = %+v, want nil on Bogus", res.Wildcard)
	}
}

// TestValidate_NoWildcard_StillSecure sanity-checks that a regular
// (non-wildcard) positive answer keeps Result.Wildcard nil. Reuses
// the buildChain fixture from chain_test.go.
func TestValidate_NoWildcard_StillSecure(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(anchors),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure", res.Verdict)
	}
	if res.Wildcard != nil {
		t.Errorf("Wildcard = %+v, want nil for non-wildcard answer", res.Wildcard)
	}
}
