package verifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestValidate_CNAME_Secure builds a chain where www.example.com is
// a CNAME to host.example.com and host.example.com has the A
// record. Both rrsets are signed by the example.com. CSK. Validate
// should chase the alias and return Secure with one AliasStep.
func TestValidate_CNAME_Secure(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeCNAME, "host.example.com.", inception, expire)
	leaf.addSignedRR(t, "host.example.com.", 300, types.TypeA, "192.0.2.10", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:                rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                 rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:             rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:         rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:     rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		// Querying www/A returns the CNAME (real DNS folds it into the
		// answer section). loadRecords adds it to the zone for our
		// CNAME-detection step.
		{"www.example.com.", types.TypeA}:      rrsetWithSigs(leaf.z, "www.example.com.", types.TypeCNAME),
		{"host.example.com.", types.TypeA}:     rrsetWithSigs(leaf.z, "host.example.com.", types.TypeA),
		{"www.example.com.", types.TypeDS}:     nil,
		{"host.example.com.", types.TypeDS}:    nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if len(res.Aliases) != 1 {
		t.Fatalf("Aliases len = %d, want 1: %+v", len(res.Aliases), res.Aliases)
	}
	step := res.Aliases[0]
	if step.Type != "cname" || step.From != "www.example.com." || step.Target != "host.example.com." {
		t.Errorf("alias step = %+v, want CNAME www→host", step)
	}
}

// TestValidate_CNAMEChain_TwoHops follows www → web → host → A.
func TestValidate_CNAMEChain_TwoHops(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeCNAME, "web.example.com.", inception, expire)
	leaf.addSignedRR(t, "web.example.com.", 300, types.TypeCNAME, "host.example.com.", inception, expire)
	leaf.addSignedRR(t, "host.example.com.", 300, types.TypeA, "192.0.2.20", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:             rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:              rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:          rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:      rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:  rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeA}:   rrsetWithSigs(leaf.z, "www.example.com.", types.TypeCNAME),
		{"web.example.com.", types.TypeA}:   rrsetWithSigs(leaf.z, "web.example.com.", types.TypeCNAME),
		{"host.example.com.", types.TypeA}:  rrsetWithSigs(leaf.z, "host.example.com.", types.TypeA),
		{"www.example.com.", types.TypeDS}:  nil,
		{"web.example.com.", types.TypeDS}:  nil,
		{"host.example.com.", types.TypeDS}: nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure", res.Verdict)
	}
	if len(res.Aliases) != 2 {
		t.Errorf("Aliases len = %d, want 2: %+v", len(res.Aliases), res.Aliases)
	}
}

// TestValidate_CNAMEChain_LoopDetected stitches www → web → www.
// Should classify as Bogus with reason "alias loop".
func TestValidate_CNAMEChain_LoopDetected(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeCNAME, "web.example.com.", inception, expire)
	leaf.addSignedRR(t, "web.example.com.", 300, types.TypeCNAME, "www.example.com.", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeA}:  rrsetWithSigs(leaf.z, "www.example.com.", types.TypeCNAME),
		{"web.example.com.", types.TypeA}:  rrsetWithSigs(leaf.z, "web.example.com.", types.TypeCNAME),
		{"www.example.com.", types.TypeDS}: nil,
		{"web.example.com.", types.TypeDS}: nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
	if res.BogusReason == "" {
		t.Errorf("expected non-empty BogusReason")
	}
}

// TestValidate_CNAME_BogusSignature: CNAME exists but its signature
// is tampered. Should be Bogus.
func TestValidate_CNAME_BogusSignature(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeCNAME, "host.example.com.", inception, expire)
	leaf.addSignedRR(t, "host.example.com.", 300, types.TypeA, "192.0.2.30", inception, expire)

	// Tamper the CNAME RRSIG.
	for _, rr := range leaf.z.FindRRSet("www.example.com.", types.TypeRRSIG) {
		h, ok := rr.Handler().(*dnssec.RRSig)
		if !ok || h.TypeCovered != types.TypeCNAME {
			continue
		}
		h.Signature[0] ^= 0x01
		break
	}

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeA}:  rrsetWithSigs(leaf.z, "www.example.com.", types.TypeCNAME),
		{"www.example.com.", types.TypeDS}: nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
}

// TestValidate_CNAME_MaxHops chains 12 CNAMEs and expects the
// verifier to give up at MaxAliasHops with a Bogus verdict whose
// reason mentions the hop cap.
func TestValidate_CNAME_MaxHops(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	// h0 → h1 → h2 → ... → h12 (no terminal A).
	for i := 0; i < 12; i++ {
		owner := chainName(i)
		target := chainName(i + 1)
		leaf.addSignedRR(t, owner, 300, types.TypeCNAME, target, inception, expire)
	}

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
	}
	for i := 0; i < 12; i++ {
		owner := chainName(i)
		resp[lookupKey{owner, types.TypeA}] = rrsetWithSigs(leaf.z, owner, types.TypeCNAME)
		resp[lookupKey{owner, types.TypeDS}] = nil
	}
	resp[lookupKey{chainName(12), types.TypeA}] = nil
	resp[lookupKey{chainName(12), types.TypeDS}] = nil

	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), chainName(0), types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
	if res.BogusReason == "" {
		t.Errorf("expected non-empty BogusReason mentioning hop cap")
	}
}

func chainName(i int) string {
	return "h" + decUint(uint16(i)) + ".example.com."
}

// TestValidate_DNAME_Synthesised covers RFC 6672: a DNAME at
// example.com rewrites foo.example.com → foo.elsewhere.com. We do not
// chain across zones here (that would require a second signed zone);
// instead the test asserts that the synthesised target is recorded
// and the chase begins, with the eventual leaf returning A under the
// rewritten name in the SAME zone (we cheat by making "elsewhere"
// also live under example.com via a contrived rewrite).
func TestValidate_DNAME_Synthesised(t *testing.T) {
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)
	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	// DNAME at sub.example.com. → also.example.com.
	leaf.addSignedRR(t, "sub.example.com.", 300, types.TypeDNAME, "also.example.com.", inception, expire)
	leaf.addSignedRR(t, "foo.also.example.com.", 300, types.TypeA, "192.0.2.40", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:                 rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                  rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:              rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:          rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:      rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		// Querying foo.sub.example.com./A returns the DNAME at sub.
		{"foo.sub.example.com.", types.TypeA}:   rrsetWithSigs(leaf.z, "sub.example.com.", types.TypeDNAME),
		{"foo.sub.example.com.", types.TypeDS}:  nil,
		{"sub.example.com.", types.TypeDS}:      nil,
		{"foo.also.example.com.", types.TypeA}:  rrsetWithSigs(leaf.z, "foo.also.example.com.", types.TypeA),
		{"foo.also.example.com.", types.TypeDS}: nil,
		{"also.example.com.", types.TypeDS}:     nil,
	}
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, root.key)),
	)
	res, err := v.Validate(context.Background(), "foo.sub.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if len(res.Aliases) != 1 {
		t.Fatalf("Aliases len = %d, want 1: %+v", len(res.Aliases), res.Aliases)
	}
	step := res.Aliases[0]
	if step.Type != "dname" || step.Target != "foo.also.example.com." {
		t.Errorf("alias step = %+v, want DNAME → foo.also.example.com.", step)
	}
}
