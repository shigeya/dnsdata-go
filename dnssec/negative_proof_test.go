package dnssec_test

import (
	"encoding/hex"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
)

// ---- NSEC -------------------------------------------------------------

func TestNSEC_MatchesName(t *testing.T) {
	n, err := dnssec.ParseNSEC(nil, "host.example.com. NS")
	if err != nil {
		t.Fatalf("ParseNSEC: %v", err)
	}
	cases := []struct {
		owner string
		qname string
		want  bool
	}{
		{"foo.example.com.", "FOO.example.com.", true},
		{"foo.example.com.", "foo.example.COM", true},
		{"foo.example.com.", "bar.example.com.", false},
	}
	for _, c := range cases {
		if got := n.MatchesName(c.owner, c.qname); got != c.want {
			t.Errorf("MatchesName(%q, %q) = %v, want %v", c.owner, c.qname, got, c.want)
		}
	}
}

func TestNSEC_CoversName(t *testing.T) {
	// NSEC at b.example. → next d.example. The covered range is
	// strictly (b.example., d.example.) — endpoints excluded.
	n, err := dnssec.ParseNSEC(nil, "d.example. NS")
	if err != nil {
		t.Fatalf("ParseNSEC: %v", err)
	}
	cases := []struct {
		owner string
		qname string
		want  bool
	}{
		{"b.example.", "c.example.", true},
		{"b.example.", "b.example.", false}, // matches owner, not covered
		{"b.example.", "d.example.", false}, // matches next, not covered
		{"b.example.", "a.example.", false}, // before owner
		{"b.example.", "z.example.", false}, // after next
	}
	for _, c := range cases {
		if got := n.CoversName(c.owner, c.qname); got != c.want {
			t.Errorf("CoversName(owner=%q, qname=%q) = %v, want %v", c.owner, c.qname, got, c.want)
		}
	}
}

func TestNSEC_CoversName_Wrap(t *testing.T) {
	// Zone-trailing NSEC: owner z.example., next back to apex
	// (example.). Range covers names greater than z.example. AND names
	// less than example. — i.e. nothing under example. that is between
	// "z.example." and "example.".
	n, err := dnssec.ParseNSEC(nil, "example. NS SOA")
	if err != nil {
		t.Fatalf("ParseNSEC: %v", err)
	}
	if !n.CoversName("z.example.", "zz.example.") {
		t.Errorf("expected wrap-NSEC to cover zz.example.")
	}
	if n.CoversName("z.example.", "a.example.") {
		t.Errorf("a.example. is less than example. so it is NOT covered by the wrap NSEC")
	}
}

func TestNSEC_ProvesNoDS(t *testing.T) {
	cases := []struct {
		name string
		v    string
		want bool
	}{
		{"signed delegation", "next.example. NS RRSIG NSEC", true},
		{"apex (SOA present)", "next.example. NS SOA RRSIG NSEC", false},
		{"DS present", "next.example. NS DS RRSIG NSEC", false},
		{"no NS", "next.example. A RRSIG NSEC", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := dnssec.ParseNSEC(nil, c.v)
			if err != nil {
				t.Fatalf("ParseNSEC: %v", err)
			}
			if got := n.ProvesNoDS(); got != c.want {
				t.Errorf("ProvesNoDS() = %v, want %v", got, c.want)
			}
		})
	}
}

// ---- NSEC3 ------------------------------------------------------------

func TestNSEC3_HasOptOut(t *testing.T) {
	// Flags=0 → no opt-out.
	n0, err := dnssec.ParseNSEC3(nil, "1 0 1 AB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	if n0.HasOptOut() {
		t.Errorf("Flags=0 reports HasOptOut=true")
	}
	// Flags=1 → opt-out.
	n1, err := dnssec.ParseNSEC3(nil, "1 1 1 AB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	if !n1.HasOptOut() {
		t.Errorf("Flags=1 reports HasOptOut=false")
	}
}

func TestNSEC3_CoversHash(t *testing.T) {
	// NextHashedOwner decoded from base32hex "08" → byte slice
	// {0x00, 0x40} per the base32hex alphabet semantics is hard to
	// build by hand. Use the parser to obtain it, then test against
	// pre-computed hash bytes.
	n, err := dnssec.ParseNSEC3(nil, "1 0 1 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	owner := bytesFromHex(t, "01000000000000000000000000000000000000ff")
	next := n.NextHashedOwner // whatever the parser produced
	// Hash strictly between owner (01 00 …) and next is "covered".
	inside := append([]byte(nil), next...)
	inside[len(inside)-1]-- // one byte less than next
	if !tBytes(t,inside).between(owner, next) {
		t.Logf("self-check: inside %x is between owner %x and next %x", inside, owner, next)
	}
	if !n.CoversHash(owner, inside) {
		t.Errorf("expected CoversHash(owner, inside) = true")
	}
	// Endpoints are not covered.
	if n.CoversHash(owner, owner) {
		t.Errorf("owner endpoint must NOT be reported as covered (that is a match)")
	}
	if n.CoversHash(owner, next) {
		t.Errorf("next endpoint must NOT be reported as covered")
	}
	// A target before owner is outside.
	outside := bytesFromHex(t, "00ff000000000000000000000000000000000000")
	if n.CoversHash(owner, outside) {
		t.Errorf("target before owner should not be covered")
	}
}

func TestNSEC3_CoversHash_Wrap(t *testing.T) {
	// Owner near zone end, next wraps back to a low hash → any target
	// greater than owner OR less than next is covered.
	n, err := dnssec.ParseNSEC3(nil, "1 0 0 - 04000000000000000000000000000000 NS SOA")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	owner := bytesFromHex(t, "f0000000000000000000000000000000")
	greater := bytesFromHex(t, "ff000000000000000000000000000000")
	less := bytesFromHex(t, "01000000000000000000000000000000")
	if !n.CoversHash(owner, greater) {
		t.Errorf("wrap: expected greater than owner to be covered")
	}
	if !n.CoversHash(owner, less) {
		t.Errorf("wrap: expected less than next to be covered")
	}
}

func TestNSEC3_ProvesNoDS(t *testing.T) {
	// NS only → signed delegation, proves no-DS.
	yes, err := dnssec.ParseNSEC3(nil, "1 0 1 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	if !yes.ProvesNoDS() {
		t.Errorf("NS-only NSEC3 should prove no-DS")
	}
	// DS bit set → cannot prove no-DS.
	no, err := dnssec.ParseNSEC3(nil, "1 0 1 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS DS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	if no.ProvesNoDS() {
		t.Errorf("NSEC3 with DS bit set must not prove no-DS")
	}
}

func TestOwnerHashFromName(t *testing.T) {
	// The NSEC3 parser already decodes the next-hashed-owner field
	// using base32hex; reuse the same encoded value so the test does
	// not have to embed a hand-computed string. Decoding the *leftmost
	// label* of an owner name must yield identical bytes.
	n, err := dnssec.ParseNSEC3(nil, "1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	got, err := dnssec.OwnerHashFromName("2T7B4G4VSA5SMI47K61MV5BV1A22BOJR.example.")
	if err != nil {
		t.Fatalf("OwnerHashFromName: %v", err)
	}
	if !tBytes(t, got).equals(n.NextHashedOwner) {
		t.Errorf("decoded leftmost label = %x, want %x", got, n.NextHashedOwner)
	}
}

func TestOwnerHashFromName_Errors(t *testing.T) {
	if _, err := dnssec.OwnerHashFromName(""); err == nil {
		t.Errorf("expected error for empty owner")
	}
	if _, err := dnssec.OwnerHashFromName(".invalid."); err == nil {
		t.Errorf("expected error for owner with empty leftmost label")
	}
}

// ---- test helpers -----------------------------------------------------

type testBytes []byte

func tBytes(t *testing.T, b []byte) testBytes {
	t.Helper()
	return testBytes(b)
}

func (a testBytes) equals(b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (a testBytes) between(lo, hi []byte) bool {
	// strict
	if a.compare(lo) <= 0 {
		return false
	}
	if a.compare(hi) >= 0 {
		return false
	}
	return true
}

func (a testBytes) compare(b []byte) int {
	la, lb := len(a), len(b)
	n := la
	if lb < n {
		n = lb
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case la < lb:
		return -1
	case la > lb:
		return 1
	}
	return 0
}

func bytesFromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
