package verifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// twoBranchChain is a signed tree with two leaf zones under different
// TLDs, so an alias can cross from example.com. to example.net.:
//
//	.  ─┬─ com. ── example.com.
//	    └─ net. ── example.net.
type twoBranchChain struct {
	root, com, net, src, dst *signedZone
	inception, expire        int64
}

func newTwoBranchChain(t *testing.T) *twoBranchChain {
	t.Helper()
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()
	c := &twoBranchChain{
		root:      newSignedZone(t, ".", inception, expire),
		com:       newSignedZone(t, "com.", inception, expire),
		net:       newSignedZone(t, "net.", inception, expire),
		src:       newSignedZone(t, "example.com.", inception, expire),
		dst:       newSignedZone(t, "example.net.", inception, expire),
		inception: inception,
		expire:    expire,
	}
	addAndSignDS(t, c.root, "com.", c.com.key, inception, expire)
	addAndSignDS(t, c.root, "net.", c.net.key, inception, expire)
	addAndSignDS(t, c.com, "example.com.", c.src.key, inception, expire)
	addAndSignDS(t, c.net, "example.net.", c.dst.key, inception, expire)
	return c
}

// responses returns the delegation part of the mock resolver's table.
// Tests add the leaf queries on top.
func (c *twoBranchChain) responses() map[lookupKey][]*zone.ResourceRecord {
	return map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(c.root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(c.root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(c.com.z, "com.", types.TypeDNSKEY),
		{"net.", types.TypeDS}:             rrsetWithSigs(c.root.z, "net.", types.TypeDS),
		{"net.", types.TypeDNSKEY}:         rrsetWithSigs(c.net.z, "net.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(c.com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(c.src.z, "example.com.", types.TypeDNSKEY),
		{"example.net.", types.TypeDS}:     rrsetWithSigs(c.net.z, "example.net.", types.TypeDS),
		{"example.net.", types.TypeDNSKEY}: rrsetWithSigs(c.dst.z, "example.net.", types.TypeDNSKEY),
	}
}

func (c *twoBranchChain) validate(t *testing.T, resp map[lookupKey][]*zone.ResourceRecord, qname string, qtype uint16) *verifier.Result {
	t.Helper()
	v, err := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, c.root.key)),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res, err := v.Validate(context.Background(), qname, qtype)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return res
}

// unsignedRR builds a record with no RRSIG, the way a server
// synthesises a CNAME from a DNAME (RFC 6672 §5.3.1).
func unsignedRR(t *testing.T, owner string, qtype uint16, value string) *zone.ResourceRecord {
	t.Helper()
	typeName, err := types.RRTypeToString(qtype)
	if err != nil {
		t.Fatalf("RRTypeToString(%d): %v", qtype, err)
	}
	rr, err := zone.NewResourceRecord(owner, 300, "IN", typeName, value)
	if err != nil {
		t.Fatalf("NewResourceRecord %s/%s: %v", owner, typeName, err)
	}
	return rr
}

func concatRRs(sets ...[]*zone.ResourceRecord) []*zone.ResourceRecord {
	var out []*zone.ResourceRecord
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

func assertSecureAlias(t *testing.T, res *verifier.Result, aliasType, from, target string, qtype uint16) {
	t.Helper()
	if res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Verdict = %s, want secure (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if len(res.Aliases) != 1 {
		t.Fatalf("Aliases len = %d, want 1: %+v", len(res.Aliases), res.Aliases)
	}
	step := res.Aliases[0]
	if step.Type != aliasType || step.From != from || step.Target != target {
		t.Errorf("alias step = %+v, want %s %s → %s", step, aliasType, from, target)
	}
	if res.Answer == nil {
		t.Fatal("Answer is nil, want the target's rrset")
	}
	if res.Answer.Name != target || res.Answer.Type != qtype {
		t.Errorf("Answer = %s/%d, want %s/%d", res.Answer.Name, res.Answer.Type, target, qtype)
	}
}

// dnameAtApex puts "example.com. DNAME example.net." and a TXT at the
// rewritten name, and returns the records an authoritative server for
// example.com. sends for www.example.com.: the signed DNAME plus the
// unsigned CNAME it synthesised.
func dnameAtApex(t *testing.T, c *twoBranchChain) []*zone.ResourceRecord {
	t.Helper()
	c.src.addSignedRR(t, "example.com.", 300, types.TypeDNAME, "example.net.", c.inception, c.expire)
	c.dst.addSignedRR(t, "www.example.net.", 300, types.TypeTXT, `"hello"`, c.inception, c.expire)
	return concatRRs(
		rrsetWithSigs(c.src.z, "example.com.", types.TypeDNAME),
		[]*zone.ResourceRecord{unsignedRR(t, "www.example.com.", types.TypeCNAME, "www.example.net.")},
	)
}

// TestValidate_DNAME_WithSynthesisedCNAME_Authoritative: the answer
// for www.example.com./TXT carries the DNAME at the apex and the
// CNAME synthesised from it, which has no RRSIG (RFC 6672 §5.3.1). The
// CNAME must not be validated on its own; the DNAME is what is signed.
func TestValidate_DNAME_WithSynthesisedCNAME_Authoritative(t *testing.T) {
	c := newTwoBranchChain(t)
	dnameAnswer := dnameAtApex(t, c)

	resp := c.responses()
	resp[lookupKey{"www.example.com.", types.TypeTXT}] = dnameAnswer
	resp[lookupKey{"www.example.com.", types.TypeDS}] = dnameAnswer
	resp[lookupKey{"www.example.net.", types.TypeTXT}] = rrsetWithSigs(c.dst.z, "www.example.net.", types.TypeTXT)

	res := c.validate(t, resp, "www.example.com.", types.TypeTXT)
	assertSecureAlias(t, res, "dname", "www.example.com.", "www.example.net.", types.TypeTXT)
}

// TestValidate_DNAME_RecursiveResponse: a recursive resolver follows
// the DNAME itself and puts the target's TXT (owner www.example.net.)
// into the same answer.
func TestValidate_DNAME_RecursiveResponse(t *testing.T) {
	c := newTwoBranchChain(t)
	dnameAnswer := dnameAtApex(t, c)
	targetTXT := rrsetWithSigs(c.dst.z, "www.example.net.", types.TypeTXT)

	resp := c.responses()
	resp[lookupKey{"www.example.com.", types.TypeTXT}] = concatRRs(dnameAnswer, targetTXT)
	resp[lookupKey{"www.example.net.", types.TypeTXT}] = targetTXT

	res := c.validate(t, resp, "www.example.com.", types.TypeTXT)
	assertSecureAlias(t, res, "dname", "www.example.com.", "www.example.net.", types.TypeTXT)
}

// TestValidate_CNAME_RecursiveResponse: a recursive resolver returns
// the signed CNAME and the target's rrset in one answer. Records of
// the asked type whose owner is the target must not be counted as the
// qname's own rrset.
func TestValidate_CNAME_RecursiveResponse(t *testing.T) {
	c := newTwoBranchChain(t)
	c.src.addSignedRR(t, "www.example.com.", 300, types.TypeCNAME, "host.example.net.", c.inception, c.expire)
	c.dst.addSignedRR(t, "host.example.net.", 300, types.TypeTXT, `"hello"`, c.inception, c.expire)
	targetTXT := rrsetWithSigs(c.dst.z, "host.example.net.", types.TypeTXT)

	resp := c.responses()
	resp[lookupKey{"www.example.com.", types.TypeTXT}] = concatRRs(
		rrsetWithSigs(c.src.z, "www.example.com.", types.TypeCNAME),
		targetTXT,
	)
	resp[lookupKey{"host.example.net.", types.TypeTXT}] = targetTXT

	res := c.validate(t, resp, "www.example.com.", types.TypeTXT)
	assertSecureAlias(t, res, "cname", "www.example.com.", "host.example.net.", types.TypeTXT)
}

// TestValidate_UnsignedCNAMEWithoutDNAME_IsBogus guards the other
// side: an unsigned CNAME with no DNAME above it is still Bogus.
func TestValidate_UnsignedCNAMEWithoutDNAME_IsBogus(t *testing.T) {
	c := newTwoBranchChain(t)
	c.dst.addSignedRR(t, "www.example.net.", 300, types.TypeTXT, `"hello"`, c.inception, c.expire)

	resp := c.responses()
	resp[lookupKey{"www.example.com.", types.TypeTXT}] = []*zone.ResourceRecord{
		unsignedRR(t, "www.example.com.", types.TypeCNAME, "www.example.net."),
	}
	resp[lookupKey{"www.example.net.", types.TypeTXT}] = rrsetWithSigs(c.dst.z, "www.example.net.", types.TypeTXT)

	res := c.validate(t, resp, "www.example.com.", types.TypeTXT)
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
}
