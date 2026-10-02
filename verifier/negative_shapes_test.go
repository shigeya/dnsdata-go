package verifier_test

import (
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// The tests in this file cover NOERROR/NODATA answers whose proof is
// not a plain matching NSEC: wildcard NODATA (RFC 4035 §3.1.3.4,
// RFC 5155 §7.2.5) and empty non-terminals. None of them may be
// classified as NXDOMAIN.

// TestValidate_WildcardNoData_NSEC: example.com. has "*.example.com.
// TXT". A query for foo.bar.example.com./A is answered with one NSEC
// at the wildcard that both covers the qname and matches the wildcard
// with a bitmap lacking A.
func TestValidate_WildcardNoData_NSEC(t *testing.T) {
	c := newTwoBranchChain(t)
	c.src.addSignedRR(t, "*.example.com.", 300, types.TypeNSEC, "example.com. TXT RRSIG NSEC", c.inception, c.expire)

	resp := c.responses()
	resp[lookupKey{"foo.bar.example.com.", types.TypeA}] = rrsetWithSigs(c.src.z, "*.example.com.", types.TypeNSEC)

	res := c.validate(t, resp, "foo.bar.example.com.", types.TypeA)
	if res.Verdict != verifier.VerdictSecureNoData {
		t.Fatalf("Verdict = %s, want secure-nodata (reason=%q)", res.Verdict, res.NegativeReason)
	}
	if !strings.Contains(res.NegativeReason, "wildcard") {
		t.Errorf("NegativeReason = %q, want wildcard mention", res.NegativeReason)
	}
}

// TestValidate_WildcardWithQType_NSEC_NotNegative: same shape, but the
// wildcard owns the asked type, so the server should have synthesised
// an answer. Neither NODATA nor NXDOMAIN is proven.
func TestValidate_WildcardWithQType_NSEC_NotNegative(t *testing.T) {
	c := newTwoBranchChain(t)
	c.src.addSignedRR(t, "*.example.com.", 300, types.TypeNSEC, "example.com. A TXT RRSIG NSEC", c.inception, c.expire)

	resp := c.responses()
	resp[lookupKey{"foo.example.com.", types.TypeA}] = rrsetWithSigs(c.src.z, "*.example.com.", types.TypeNSEC)

	res := c.validate(t, resp, "foo.example.com.", types.TypeA)
	if res.Verdict == verifier.VerdictSecureNoData || res.Verdict == verifier.VerdictSecureNXDomain {
		t.Errorf("Verdict = %s, want neither secure-nodata nor secure-nxdomain (reason=%q)", res.Verdict, res.NegativeReason)
	}
}

// TestValidate_EmptyNonTerminal_NSEC: a.b.example.com. exists, so
// b.example.com. is an empty non-terminal. The NSEC covering
// b.example.com. has a next name below it; that proves NODATA.
func TestValidate_EmptyNonTerminal_NSEC(t *testing.T) {
	c := newTwoBranchChain(t)
	c.src.addSignedRR(t, "example.com.", 300, types.TypeNSEC, "a.b.example.com. NS SOA RRSIG NSEC DNSKEY", c.inception, c.expire)

	resp := c.responses()
	resp[lookupKey{"b.example.com.", types.TypeA}] = rrsetWithSigs(c.src.z, "example.com.", types.TypeNSEC)

	res := c.validate(t, resp, "b.example.com.", types.TypeA)
	if res.Verdict != verifier.VerdictSecureNoData {
		t.Fatalf("Verdict = %s, want secure-nodata (reason=%q)", res.Verdict, res.NegativeReason)
	}
	if !strings.Contains(res.NegativeReason, "empty non-terminal") {
		t.Errorf("NegativeReason = %q, want empty non-terminal mention", res.NegativeReason)
	}
}

// nsec3Hash returns H(name) with SHA-1, no salt, zero iterations.
func nsec3Hash(t *testing.T, name string) []byte {
	t.Helper()
	h, err := dnssec.ComputeNSEC3Hash(name, 1, 0, nil)
	if err != nil {
		t.Fatalf("hash %s: %v", name, err)
	}
	return h
}

// addNSEC3 signs an NSEC3 at the given owner hash with the given next
// hash and type list, and returns its owner name.
func addNSEC3(t *testing.T, c *twoBranchChain, ownerHash, next []byte, typeList ...string) string {
	t.Helper()
	owner := base32hexEncode(ownerHash) + ".example.com."
	rdata := joinSpace(append([]string{"1", "0", "0", "-", base32hexEncode(next)}, typeList...)...)
	c.src.addSignedRR(t, owner, 300, types.TypeNSEC3, rdata, c.inception, c.expire)
	return owner
}

func bumpLastByte(b []byte, delta int) []byte {
	out := append([]byte(nil), b...)
	out[len(out)-1] = byte(int(out[len(out)-1]) + delta)
	return out
}

// wildcardNSEC3Answer builds the RFC 5155 §7.2.5 shape for
// foo.bar.example.com.: an NSEC3 matching the closest encloser
// example.com., one covering the next closer bar.example.com., and
// one matching *.example.com. with wildcardTypes.
func wildcardNSEC3Answer(t *testing.T, c *twoBranchChain, wildcardTypes ...string) []*zone.ResourceRecord {
	t.Helper()
	hCE := nsec3Hash(t, "example.com.")
	hNC := nsec3Hash(t, "bar.example.com.")
	hWC := nsec3Hash(t, "*.example.com.")

	owners := []string{
		addNSEC3(t, c, hCE, bumpLastByte(hCE, 1), "NS", "SOA", "RRSIG", "DNSKEY", "NSEC3PARAM"),
		addNSEC3(t, c, bumpLastByte(hNC, -1), bumpLastByte(hNC, 1), "TXT", "RRSIG"),
		addNSEC3(t, c, hWC, bumpLastByte(hWC, 1), wildcardTypes...),
	}
	var out []*zone.ResourceRecord
	for _, o := range owners {
		out = append(out, rrsetWithSigs(c.src.z, o, types.TypeNSEC3)...)
	}
	return out
}

// TestValidate_WildcardNoData_NSEC3 is the NSEC3 form of the wildcard
// NODATA proof.
func TestValidate_WildcardNoData_NSEC3(t *testing.T) {
	c := newTwoBranchChain(t)
	answer := wildcardNSEC3Answer(t, c, "TXT", "RRSIG")

	resp := c.responses()
	resp[lookupKey{"foo.bar.example.com.", types.TypeA}] = answer

	res := c.validate(t, resp, "foo.bar.example.com.", types.TypeA)
	if res.Verdict != verifier.VerdictSecureNoData {
		t.Fatalf("Verdict = %s, want secure-nodata (reason=%q)", res.Verdict, res.NegativeReason)
	}
	if !strings.Contains(res.NegativeReason, "wildcard") {
		t.Errorf("NegativeReason = %q, want wildcard mention", res.NegativeReason)
	}
}

// TestValidate_WildcardWithQType_NSEC3_NotNegative: the wildcard owns
// the asked type, so no negative verdict may be returned.
func TestValidate_WildcardWithQType_NSEC3_NotNegative(t *testing.T) {
	c := newTwoBranchChain(t)
	answer := wildcardNSEC3Answer(t, c, "A", "TXT", "RRSIG")

	resp := c.responses()
	resp[lookupKey{"foo.bar.example.com.", types.TypeA}] = answer

	res := c.validate(t, resp, "foo.bar.example.com.", types.TypeA)
	if res.Verdict == verifier.VerdictSecureNoData || res.Verdict == verifier.VerdictSecureNXDomain {
		t.Errorf("Verdict = %s, want neither secure-nodata nor secure-nxdomain (reason=%q)", res.Verdict, res.NegativeReason)
	}
}
