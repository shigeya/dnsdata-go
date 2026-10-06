package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// The tests in this file pin down how a zone's DNSKEY rrset is
// authenticated: an RRSIG over it counts only when its signature
// verifies under a DNSKEY that is itself authenticated by a DS record
// of the parent (or by a trust anchor at the root). Injecting a key
// into the rrset, or tampering with the KSK's signature, must make the
// zone Bogus, and the SEP flag must not matter either way.

// keyAuthChain is the root → com. → example.com. fixture of buildChain,
// with the zones kept so a test can alter them before serving.
type keyAuthChain struct {
	root, com, leaf   *signedZone
	inception, expire int64
}

// newKeyAuthChain builds the chain. rootFlags and leafFlags are the
// DNSKEY flags of the root's and example.com.'s only key.
func newKeyAuthChain(t *testing.T, rootFlags, leafFlags uint16) *keyAuthChain {
	t.Helper()
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()
	c := &keyAuthChain{
		root:      newSignedZoneWithFlags(t, ".", rootFlags, inception, expire),
		com:       newSignedZone(t, "com.", inception, expire),
		leaf:      newSignedZoneWithFlags(t, "example.com.", leafFlags, inception, expire),
		inception: inception,
		expire:    expire,
	}
	addAndSignDS(t, c.root, "com.", c.com.key, inception, expire)
	addAndSignDS(t, c.com, "example.com.", c.leaf.key, inception, expire)
	c.leaf.addSignedRR(t, "www.example.com.", 300, types.TypeA, "192.0.2.10", inception, expire)
	return c
}

// responses serves the chain as it stands, for www.example.com. and
// evil.example.com.
func (c *keyAuthChain) responses() map[lookupKey][]*zone.ResourceRecord {
	return map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:            rrsetWithSigs(c.root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:             rrsetWithSigs(c.root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:         rrsetWithSigs(c.com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:     rrsetWithSigs(c.com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}: rrsetWithSigs(c.leaf.z, "example.com.", types.TypeDNSKEY),
		{"www.example.com.", types.TypeA}:  rrsetWithSigs(c.leaf.z, "www.example.com.", types.TypeA),
		{"evil.example.com.", types.TypeA}: rrsetWithSigs(c.leaf.z, "evil.example.com.", types.TypeA),
	}
}

// validate runs a Verifier over resp anchored at the chain's root key.
func (c *keyAuthChain) validate(t *testing.T, resp map[lookupKey][]*zone.ResourceRecord, qname string) *verifier.Result {
	t.Helper()
	v, err := verifier.NewVerifier(
		verifier.WithResolver(&mockResolver{responses: resp}),
		verifier.WithTrustAnchors(makeTrustAnchor(t, c.root.key)),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res, err := v.Validate(context.Background(), qname, types.TypeA)
	if err != nil {
		t.Fatalf("Validate(%s): %v", qname, err)
	}
	return res
}

// injectKey adds an attacker's DNSKEY (with flags) to s's DNSKEY rrset,
// signs the enlarged rrset with it, and signs an A record at
// evil.<zone> with it alone.
func injectKey(t *testing.T, s *signedZone, flags uint16, inception, expire int64) *dnssec.DNSKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	value := decUint(flags) + " 3 13 " + base64.StdEncoding.EncodeToString(encodeECDSAP256Coords(t, &priv.PublicKey))
	rr, err := s.z.AddRRFromParts(s.name, 3600, "IN", "DNSKEY", value)
	if err != nil {
		t.Fatalf("AddRR injected DNSKEY: %v", err)
	}
	key := rr.Handler().(*dnssec.DNSKey)
	key.SetPrivateKey(priv)
	sig, err := s.z.SignRR(s.name, 3600, types.TypeDNSKEY, key, inception, expire)
	if err != nil || sig == nil {
		t.Fatalf("SignRR DNSKEY with injected key: %v", err)
	}
	s.z.AddRR(sig)

	evil := "evil." + s.name
	if s.name == "." {
		evil = "evil."
	}
	if _, err := s.z.AddRRFromParts(evil, 300, "IN", "A", "203.0.113.66"); err != nil {
		t.Fatalf("AddRR evil A: %v", err)
	}
	asig, err := s.z.SignRR(evil, 300, types.TypeA, key, inception, expire)
	if err != nil || asig == nil {
		t.Fatalf("SignRR evil A: %v", err)
	}
	s.z.AddRR(asig)
	return key
}

// onlySigsBy drops every RRSIG in records not made by key tag keyTag.
func onlySigsBy(records []*zone.ResourceRecord, keyTag uint16) []*zone.ResourceRecord {
	var out []*zone.ResourceRecord
	for _, rr := range records {
		if sig, ok := rr.Handler().(*dnssec.RRSig); ok && sig.KeyTag != keyTag {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// firstRRSIG returns the first RRSIG record in records.
func firstRRSIG(t *testing.T, records []*zone.ResourceRecord) *zone.ResourceRecord {
	t.Helper()
	for _, rr := range records {
		if rr.Type == types.TypeRRSIG {
			return rr
		}
	}
	t.Fatal("no RRSIG in records")
	return nil
}

// tamperRRSIG flips one bit of an RRSIG record's signature, in both
// its parsed handler and its presentation value.
func tamperRRSIG(t *testing.T, rr *zone.ResourceRecord) {
	t.Helper()
	sig, ok := rr.Handler().(*dnssec.RRSig)
	if !ok {
		t.Fatalf("%s is not an RRSIG", rr)
	}
	sig.Signature[0] ^= 0x01
	fields := strings.Fields(rr.Value)
	fields[len(fields)-1] = base64.StdEncoding.EncodeToString(sig.Signature)
	rr.Value = strings.Join(fields, " ")
}

func wantBogus(t *testing.T, res *verifier.Result, at string) {
	t.Helper()
	if res.Verdict != verifier.VerdictBogus {
		t.Fatalf("Verdict = %s, want bogus (BogusAt=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if res.BogusAt != at {
		t.Errorf("BogusAt = %q, want %q (reason %q)", res.BogusAt, at, res.BogusReason)
	}
}

func wantSecure(t *testing.T, res *verifier.Result) {
	t.Helper()
	if res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Verdict = %s, want secure (BogusAt=%q reason=%q)",
			res.Verdict, res.BogusAt, res.BogusReason)
	}
}

// TestValidate_TamperedKSKSignature: a KSK RRSIG over the DNSKEY rrset
// whose signature octets were altered must not authenticate the rrset,
// even though the KSK itself matches the DS (or the trust anchor).
func TestValidate_TamperedKSKSignature(t *testing.T) {
	for _, at := range []string{".", "example.com."} {
		t.Run(at, func(t *testing.T) {
			c := newKeyAuthChain(t, 257, 257)
			resp := c.responses()
			tamperRRSIG(t, firstRRSIG(t, resp[lookupKey{at, types.TypeDNSKEY}]))
			res := c.validate(t, resp, "www.example.com.")
			wantBogus(t, res, at)
		})
	}
}

// TestValidate_InjectedKeyInChildDNSKEY: a key injected into
// example.com.'s DNSKEY rrset, signing the enlarged rrset and some data
// itself, must not be trusted, whether or not it carries the SEP flag
// and whether or not the real KSK's (now stale) RRSIG is still served.
func TestValidate_InjectedKeyInChildDNSKEY(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     uint16
		keepLegit bool
	}{
		{"sep/legit sig absent", 257, false},
		{"sep/legit sig stale", 257, true},
		{"non-sep/legit sig absent", 256, false},
		{"non-sep/legit sig stale", 256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newKeyAuthChain(t, 257, 257)
			evilKey := injectKey(t, c.leaf, tc.flags, c.inception, c.expire)
			resp := c.responses()
			if !tc.keepLegit {
				k := lookupKey{"example.com.", types.TypeDNSKEY}
				resp[k] = onlySigsBy(resp[k], evilKey.KeyTag)
			}
			for _, qname := range []string{"evil.example.com.", "www.example.com."} {
				res := c.validate(t, resp, qname)
				wantBogus(t, res, "example.com.")
			}
		})
	}
}

// TestValidate_InjectedKeyInRootDNSKEY: the same attack on the root's
// DNSKEY rrset, checked against the configured trust anchor.
func TestValidate_InjectedKeyInRootDNSKEY(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     uint16
		keepLegit bool
	}{
		{"sep/legit sig absent", 257, false},
		{"sep/legit sig stale", 257, true},
		{"non-sep/legit sig absent", 256, false},
		{"non-sep/legit sig stale", 256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newKeyAuthChain(t, 257, 257)
			evilKey := injectKey(t, c.root, tc.flags, c.inception, c.expire)
			resp := c.responses()
			if !tc.keepLegit {
				k := lookupKey{".", types.TypeDNSKEY}
				resp[k] = onlySigsBy(resp[k], evilKey.KeyTag)
			}
			res := c.validate(t, resp, "www.example.com.")
			wantBogus(t, res, ".")
		})
	}
}

// TestValidate_KSKWithoutSEPFlag: the SEP flag is a hint (RFC 4034
// §2.1.1). A key that matches the DS, or the trust anchor, is the KSK
// whatever its flags say.
func TestValidate_KSKWithoutSEPFlag(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		rootFlags, leafFlags uint16
	}{
		{"child", 257, 256},
		{"root", 256, 257},
		{"both", 256, 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newKeyAuthChain(t, tc.rootFlags, tc.leafFlags)
			res := c.validate(t, c.responses(), "www.example.com.")
			wantSecure(t, res)
			last := res.Chain[len(res.Chain)-1]
			if last.SignedBy == nil || last.SignedBy.KeyTag != c.leaf.key.KeyTag {
				t.Errorf("example.com. SignedBy = %+v, want key tag %d", last.SignedBy, c.leaf.key.KeyTag)
			}
		})
	}
}
