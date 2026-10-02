package signer_test

import (
	"bytes"
	"encoding/base32"
	"slices"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

var b32hex = base32.HexEncoding.WithPadding(base32.NoPadding)

func signNSEC3(t *testing.T, params signer.NSEC3Options) *zone.Zone {
	t.Helper()
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	zsk := mustKey(t, "example.test.", "zsk", signer.FlagsZSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	opts := signOpts()
	opts.NSEC3 = &params
	signed, err := signer.SignZone(exampleZone(t, child), "example.test.", []*signer.Key{ksk, zsk}, opts)
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return signed
}

// nsec3At returns the NSEC3 for the original name, or nil.
func nsec3At(t *testing.T, signed *zone.Zone, name string, params signer.NSEC3Options) *dnssec.NSEC3 {
	t.Helper()
	h, err := dnssec.ComputeNSEC3Hash(name, 1, params.Iterations, params.Salt)
	if err != nil {
		t.Fatal(err)
	}
	rrs := signed.FindRRSet(b32hex.EncodeToString(h)+".example.test.", types.TypeNSEC3)
	if len(rrs) == 0 {
		return nil
	}
	if len(rrs) > 1 {
		t.Fatalf("%s: %d NSEC3 records", name, len(rrs))
	}
	n, err := dnssec.ParseNSEC3(nil, rrs[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// RFC 5155 §7.1: one NSEC3 per authoritative name and empty
// non-terminal, hashed; the bitmap lists the types at the original
// name, RRSIG only where something there is signed. Glue gets none.
func TestSignZone_NSEC3Chain(t *testing.T) {
	params := signer.NSEC3Options{}
	signed := signNSEC3(t, params)
	want := map[string][]uint16{
		"example.test.":        {types.TypeNS, types.TypeSOA, types.TypeRRSIG, types.TypeDNSKEY, types.TypeNSEC3PARAM},
		"key.example.test.":    {types.TypeRRSIG, 65400},
		"nods.example.test.":   {types.TypeNS},
		"ns1.example.test.":    {types.TypeA, types.TypeRRSIG},
		"sub.example.test.":    {types.TypeNS, types.TypeDS, types.TypeRRSIG},
		"*.wild.example.test.": {types.TypeA, types.TypeRRSIG},
		"wild.example.test.":   {},
		"www.example.test.":    {types.TypeA, types.TypeTXT, types.TypeRRSIG},
	}
	for name, wantTypes := range want {
		n := nsec3At(t, signed, name, params)
		if n == nil {
			t.Errorf("%s: no NSEC3", name)
			continue
		}
		slices.Sort(wantTypes)
		if !slices.Equal(n.CoveredTypes, wantTypes) {
			t.Errorf("%s: bitmap %v, want %v", name, n.CoveredTypes, wantTypes)
		}
		if n.HashAlgorithm != 1 || n.Flags != 0 || n.Iterations != 0 || len(n.Salt) != 0 {
			t.Errorf("%s: params %d %d %d %x, want RFC 9276 1 0 0 -", name, n.HashAlgorithm, n.Flags, n.Iterations, n.Salt)
		}
	}
	for _, glue := range []string{"ns.sub.example.test.", "ns.nods.example.test."} {
		if nsec3At(t, signed, glue, params) != nil {
			t.Errorf("glue %s must not have an NSEC3", glue)
		}
	}
	checkNSEC3Chain(t, signed, len(want))
	if got := countType(signed, types.TypeNSEC); got != 0 {
		t.Errorf("%d NSEC records in an NSEC3 zone", got)
	}
	param := signed.FindRRSet("example.test.", types.TypeNSEC3PARAM)
	if len(param) != 1 || param[0].Value != "1 0 0 -" {
		t.Errorf("NSEC3PARAM = %v, want one `1 0 0 -` at the apex", param)
	}
	verifyAllRRSIGs(t, signed)
}

// RFC 5155 §6: with opt-out the unsigned delegation leaves the chain
// and every NSEC3 has the opt-out flag; NSEC3PARAM keeps flags 0.
func TestSignZone_NSEC3OptOut(t *testing.T) {
	params := signer.NSEC3Options{Iterations: 5, Salt: []byte{0xaa, 0xbb}, OptOut: true}
	signed := signNSEC3(t, params)
	if nsec3At(t, signed, "nods.example.test.", params) != nil {
		t.Error("opt-out: the unsigned delegation must not have an NSEC3")
	}
	for _, name := range []string{"example.test.", "sub.example.test.", "wild.example.test.", "www.example.test."} {
		n := nsec3At(t, signed, name, params)
		if n == nil {
			t.Errorf("%s: no NSEC3", name)
			continue
		}
		if !n.HasOptOut() || n.Iterations != 5 || !bytes.Equal(n.Salt, params.Salt) {
			t.Errorf("%s: flags %d iterations %d salt %x", name, n.Flags, n.Iterations, n.Salt)
		}
	}
	checkNSEC3Chain(t, signed, 7)
	param := signed.FindRRSet("example.test.", types.TypeNSEC3PARAM)
	if len(param) != 1 || param[0].Value != "1 0 5 AABB" {
		t.Errorf("NSEC3PARAM = %v, want one `1 0 5 AABB`", param)
	}
	verifyAllRRSIGs(t, signed)
}

// checkNSEC3Chain checks that the n NSEC3 records form one closed ring
// in hash order, each signed.
func checkNSEC3Chain(t *testing.T, signed *zone.Zone, n int) {
	t.Helper()
	type link struct{ owner, next []byte }
	var links []link
	for _, rr := range signed.AllRecords() {
		if rr.Type != types.TypeNSEC3 {
			continue
		}
		owner, err := dnssec.OwnerHashFromName(rr.Label)
		if err != nil {
			t.Fatal(err)
		}
		n3, err := dnssec.ParseNSEC3(nil, rr.Value)
		if err != nil {
			t.Fatal(err)
		}
		links = append(links, link{owner, n3.NextHashedOwner})
		if len(rrsigsAt(signed, rr.Label)[types.TypeNSEC3]) == 0 {
			t.Errorf("NSEC3 at %s is not signed", rr.Label)
		}
	}
	if len(links) != n {
		t.Fatalf("%d NSEC3 records, want %d", len(links), n)
	}
	slices.SortFunc(links, func(a, b link) int { return bytes.Compare(a.owner, b.owner) })
	for i, l := range links {
		if next := links[(i+1)%len(links)].owner; !bytes.Equal(l.next, next) {
			t.Errorf("NSEC3 %s: next %s, want %s", b32hex.EncodeToString(l.owner),
				b32hex.EncodeToString(l.next), b32hex.EncodeToString(next))
		}
	}
	if len(rrsigsAt(signed, "example.test.")[types.TypeNSEC3PARAM]) == 0 {
		t.Error("NSEC3PARAM is not signed")
	}
}

func countType(z *zone.Zone, t uint16) int {
	n := 0
	for _, rr := range z.AllRecords() {
		if rr.Type == t {
			n++
		}
	}
	return n
}

func TestSignZone_NSEC3AcceptedByBIND(t *testing.T) {
	for name, params := range map[string]signer.NSEC3Options{
		"RFC 9276": {},
		"opt-out":  {Iterations: 5, Salt: []byte{0xaa, 0xbb}, OptOut: true},
	} {
		t.Run(name, func(t *testing.T) {
			ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
			zsk := mustKey(t, "example.test.", "zsk", signer.FlagsZSK)
			child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
			opts := signer.Options{
				Inception:  time.Now().Add(-time.Hour),
				Expiration: time.Now().Add(24 * time.Hour),
				NSEC3:      &params,
			}
			signed, err := signer.SignZone(exampleZone(t, child), "example.test.", []*signer.Key{ksk, zsk}, opts)
			if err != nil {
				t.Fatal(err)
			}
			checkWithBIND(t, signed)
		})
	}
}

func TestBuildNSEC3_TTLFromSOA(t *testing.T) {
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	recs, err := signer.BuildNSEC3(exampleZone(t, child), "example.test.", 0, signer.NSEC3Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 9 {
		t.Fatalf("%d records, want 8 NSEC3 and an NSEC3PARAM", len(recs))
	}
	for _, rr := range recs {
		if rr.TTL != 300 {
			t.Errorf("%s %s TTL %d, want min(SOA TTL, MINIMUM) = 300", rr.Label, types.RRTypeName(rr.Type), rr.TTL)
		}
	}
}
