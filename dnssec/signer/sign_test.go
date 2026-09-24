package signer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

var (
	testInception  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	testExpiration = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	testNow        = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
)

func mustKey(t *testing.T, owner, seed string, flags uint16) *signer.Key {
	t.Helper()
	k, err := signer.ParseBINDPrivate(owner, flags, bindPrivateECDSA(seed))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// exampleZone is example.test. with a signed delegation (sub), an
// unsigned delegation (nods), glue under both, a wildcard, and a type
// without a mnemonic.
func exampleZone(t *testing.T, childKSK *signer.Key) *zone.Zone {
	t.Helper()
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
	ds, err := childKSK.DS(signer.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	text := `$ORIGIN example.test.
$TTL 3600
@       SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@       NS  ns1.example.test.
ns1     A   192.0.2.1
www     A   192.0.2.10
www     TXT "hello" "world, longer"
key     TYPE65400 \# 4 01020304
key     TYPE65400 \# 1 62
key     TYPE65400 \# 2 6162
*.wild  A   192.0.2.20
sub     NS  ns.sub.example.test.
sub     DS  ` + ds + `
ns.sub  A   192.0.2.53
nods    NS  ns.nods.example.test.
ns.nods A   192.0.2.54
`
	var z zone.Zone
	if err := z.ReadStringStrict(text); err != nil {
		t.Fatal(err)
	}
	return &z
}

func signOpts() signer.Options {
	return signer.Options{Inception: testInception, Expiration: testExpiration}
}

func rrsigsAt(z *zone.Zone, owner string) map[uint16][]*dnssec.RRSig {
	out := map[uint16][]*dnssec.RRSig{}
	for _, rr := range z.FindRRSet(owner, types.TypeRRSIG) {
		if s, err := dnssec.ParseRRSig(nil, rr.Value); err == nil {
			out[s.TypeCovered] = append(out[s.TypeCovered], s)
		}
	}
	return out
}

func TestSignZone_NSECChain(t *testing.T) {
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	zsk := mustKey(t, "example.test.", "zsk", signer.FlagsZSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	signed, err := signer.SignZone(exampleZone(t, child), "example.test.", []*signer.Key{ksk, zsk}, signOpts())
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	want := []struct {
		owner string
		types []uint16
	}{
		{"example.test.", []uint16{types.TypeNS, types.TypeSOA, types.TypeRRSIG, types.TypeNSEC, types.TypeDNSKEY}},
		{"key.example.test.", []uint16{types.TypeRRSIG, types.TypeNSEC, 65400}},
		{"nods.example.test.", []uint16{types.TypeNS, types.TypeRRSIG, types.TypeNSEC}},
		{"ns1.example.test.", []uint16{types.TypeA, types.TypeRRSIG, types.TypeNSEC}},
		{"sub.example.test.", []uint16{types.TypeNS, types.TypeDS, types.TypeRRSIG, types.TypeNSEC}},
		{"*.wild.example.test.", []uint16{types.TypeA, types.TypeRRSIG, types.TypeNSEC}},
		{"www.example.test.", []uint16{types.TypeA, types.TypeTXT, types.TypeRRSIG, types.TypeNSEC}},
	}
	for i, w := range want {
		rrs := signed.FindRRSet(w.owner, types.TypeNSEC)
		if len(rrs) != 1 {
			t.Errorf("%s: %d NSEC records, want 1", w.owner, len(rrs))
			continue
		}
		n, err := dnssec.ParseNSEC(nil, rrs[0].Value)
		if err != nil {
			t.Fatal(err)
		}
		next := want[(i+1)%len(want)].owner
		if n.NextDomain != next {
			t.Errorf("%s: next %s, want %s", w.owner, n.NextDomain, next)
		}
		wantTypes := slices.Clone(w.types)
		slices.Sort(wantTypes)
		if !slices.Equal(n.CoveredTypes, wantTypes) {
			t.Errorf("%s: bitmap %v, want %v", w.owner, n.CoveredTypes, wantTypes)
		}
	}
	for _, glue := range []string{"ns.sub.example.test.", "ns.nods.example.test.", "wild.example.test."} {
		if len(signed.FindRRSet(glue, types.TypeNSEC)) != 0 {
			t.Errorf("%s must not have an NSEC (glue or empty non-terminal)", glue)
		}
	}
}

func TestSignZone_WhatIsSigned(t *testing.T) {
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	zsk := mustKey(t, "example.test.", "zsk", signer.FlagsZSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	signed, err := signer.SignZone(exampleZone(t, child), "example.test.", []*signer.Key{ksk, zsk}, signOpts())
	if err != nil {
		t.Fatal(err)
	}
	apex := rrsigsAt(signed, "example.test.")
	if len(apex[types.TypeDNSKEY]) != 1 || apex[types.TypeDNSKEY][0].KeyTag != ksk.KeyTag() {
		t.Errorf("DNSKEY RRset must be signed by the KSK only: %+v", apex[types.TypeDNSKEY])
	}
	if len(apex[types.TypeSOA]) != 1 || apex[types.TypeSOA][0].KeyTag != zsk.KeyTag() {
		t.Errorf("SOA must be signed by the ZSK only: %+v", apex[types.TypeSOA])
	}
	if got := len(signed.FindRRSet("example.test.", types.TypeDNSKEY)); got != 2 {
		t.Errorf("apex DNSKEY RRset has %d keys, want 2", got)
	}
	sub := rrsigsAt(signed, "sub.example.test.")
	if len(sub[types.TypeNS]) != 0 || len(sub[types.TypeDS]) != 1 || len(sub[types.TypeNSEC]) != 1 {
		t.Errorf("delegation: NS unsigned, DS and NSEC signed; got %v", sub)
	}
	for _, unsigned := range []string{"ns.sub.example.test.", "ns.nods.example.test."} {
		if len(signed.FindRRSet(unsigned, types.TypeRRSIG)) != 0 {
			t.Errorf("glue %s must not be signed", unsigned)
		}
	}
	if len(rrsigsAt(signed, "nods.example.test.")[types.TypeNS]) != 0 {
		t.Error("unsigned delegation NS must not be signed")
	}
	wild := rrsigsAt(signed, "*.wild.example.test.")[types.TypeA]
	if len(wild) != 1 || wild[0].Labels != 3 {
		t.Errorf("wildcard RRSIG labels: %+v, want 3", wild)
	}
	key := rrsigsAt(signed, "key.example.test.")[65400]
	if len(key) != 1 || key[0].Labels != 3 || key[0].Signer != "example.test." {
		t.Fatalf("TYPE65400 RRSIG: %+v", key)
	}
	if key[0].Inception != testInception.Unix() || key[0].Expire != testExpiration.Unix() {
		t.Errorf("RRSIG window = %d..%d", key[0].Inception, key[0].Expire)
	}
}

// Every RRSIG in the signed zone verifies under the zone's own DNSKEYs.
func TestSignZone_SignaturesVerify(t *testing.T) {
	dnssec.RegisterHandlers()
	for _, name := range []string{"KSK+ZSK", "CSK"} {
		t.Run(name, func(t *testing.T) {
			keys := []*signer.Key{mustKey(t, "example.test.", "ksk", signer.FlagsKSK)}
			if name == "KSK+ZSK" {
				keys = append(keys, mustKey(t, "example.test.", "zsk", signer.FlagsZSK))
			}
			child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
			signed, err := signer.SignZone(exampleZone(t, child), "example.test.", keys, signOpts())
			if err != nil {
				t.Fatal(err)
			}
			verifyAllRRSIGs(t, signed)
		})
	}
}

func verifyAllRRSIGs(t *testing.T, signed *zone.Zone) {
	t.Helper()
	dnssec.RegisterHandlers()
	dz := dnssec.NewZone()
	for _, rr := range signed.AllRecords() {
		cp, err := zone.NewResourceRecord(rr.Label, rr.TTL, rr.Class, rr.Type, rr.Value)
		if err != nil {
			t.Fatal(err)
		}
		dz.AddRR(cp)
	}
	dz.SetClock(func() time.Time { return testNow })
	count := 0
	for _, rr := range dz.AllRecords() {
		if rr.Type != types.TypeRRSIG {
			continue
		}
		sig := rr.Handler().(*dnssec.RRSig)
		ok, err := dz.VerifyRRSIG(rr.Label, sig.TypeCovered, sig, dnssec.KeyModeNone)
		if err != nil || !ok {
			t.Errorf("RRSIG %s/%s did not verify: %v", rr.Label, types.RRTypeName(sig.TypeCovered), err)
		}
		count++
	}
	if count == 0 {
		t.Fatal("no RRSIGs")
	}
}

func TestSignZone_Root(t *testing.T) {
	ksk := mustKey(t, ".", "root", signer.FlagsKSK)
	tld := mustKey(t, "test.", "tld", signer.FlagsKSK)
	ds, _ := tld.DS(signer.DigestSHA256)
	dnssec.RegisterHandlers()
	var z zone.Zone
	if err := z.ReadStringStrict(". 86400 SOA a.root.test. h.root.test. 1 2 3 4 5\n" +
		". 86400 NS a.root.test.\ntest. 86400 NS a.root.test.\ntest. 86400 DS " + ds + "\n"); err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignZone(&z, ".", []*signer.Key{ksk}, signOpts())
	if err != nil {
		t.Fatal(err)
	}
	sigs := rrsigsAt(signed, ".")
	if len(sigs[types.TypeDNSKEY]) != 1 || sigs[types.TypeDNSKEY][0].Labels != 0 {
		t.Errorf("root DNSKEY RRSIG labels must be 0: %+v", sigs[types.TypeDNSKEY])
	}
	if ds := rrsigsAt(signed, "test.")[types.TypeDS]; len(ds) != 1 || ds[0].Labels != 1 {
		t.Errorf("test. DS RRSIG labels must be 1: %+v", ds)
	}
	verifyAllRRSIGs(t, signed)
}

func TestSignZone_ReSignDropsOldSignatures(t *testing.T) {
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	in := exampleZone(t, child)
	before := len(in.AllRecords())
	once, err := signer.SignZone(in, "example.test.", []*signer.Key{ksk}, signOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(in.AllRecords()) != before {
		t.Error("SignZone modified its input")
	}
	twice, err := signer.SignZone(once, "example.test.", []*signer.Key{ksk}, signOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(twice.AllRecords()) != len(once.AllRecords()) {
		t.Errorf("re-signing grew the zone from %d to %d records", len(once.AllRecords()), len(twice.AllRecords()))
	}
}

func TestSignZone_Errors(t *testing.T) {
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	other := mustKey(t, "other.test.", "other", signer.FlagsKSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	z := exampleZone(t, child)
	outside := exampleZone(t, child)
	if _, err := outside.AddRRFromParts("www.other.test.", 60, "IN", "A", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		z    *zone.Zone
		keys []*signer.Key
		opts signer.Options
	}{
		{"no keys", z, nil, signOpts()},
		{"key for another zone", z, []*signer.Key{other}, signOpts()},
		{"no inception", z, []*signer.Key{ksk}, signer.Options{Expiration: testExpiration}},
		{"no expiration", z, []*signer.Key{ksk}, signer.Options{Inception: testInception}},
		{"record outside the apex", outside, []*signer.Key{ksk}, signOpts()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := signer.SignZone(tc.z, "example.test.", tc.keys, tc.opts); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestBuildNSEC_TTLFromSOA(t *testing.T) {
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	nsecs, err := signer.BuildNSEC(exampleZone(t, child), "example.test.", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nsecs) == 0 {
		t.Fatal("no NSEC records")
	}
	for _, rr := range nsecs {
		if rr.TTL != 300 { // RFC 9077: min(SOA TTL 3600, SOA MINIMUM 300)
			t.Errorf("%s NSEC TTL = %d, want 300", rr.Label, rr.TTL)
		}
	}
}

// C-5 acceptance and an independent check of C-6: BIND's zone checker
// loads the canonical output and BIND's DNSSEC verifier accepts the
// signatures and the NSEC chain.
func TestSignZone_AcceptedByBIND(t *testing.T) {
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	zsk := mustKey(t, "example.test.", "zsk", signer.FlagsZSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	opts := signer.Options{Inception: time.Now().Add(-time.Hour), Expiration: time.Now().Add(24 * time.Hour)}
	signed, err := signer.SignZone(exampleZone(t, child), "example.test.", []*signer.Key{ksk, zsk}, opts)
	if err != nil {
		t.Fatal(err)
	}
	text, err := signed.PrintCanonical(0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "example.test.zone")
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	if checkzone, err := exec.LookPath("named-checkzone"); err == nil {
		ran = true
		if out, err := exec.Command(checkzone, "example.test", path).CombinedOutput(); err != nil {
			t.Errorf("named-checkzone rejected the zone: %v\n%s\n%s", err, out, text)
		}
	}
	if verify, err := exec.LookPath("dnssec-verify"); err == nil {
		ran = true
		if out, err := exec.Command(verify, "-o", "example.test", path).CombinedOutput(); err != nil {
			t.Errorf("dnssec-verify rejected the zone: %v\n%s\n%s", err, out, text)
		}
	}
	if !ran {
		t.Skip("neither named-checkzone nor dnssec-verify installed")
	}
}

func TestSignZone_OutputHasNoStrayTypes(t *testing.T) {
	ksk := mustKey(t, "example.test.", "ksk", signer.FlagsKSK)
	child := mustKey(t, "sub.example.test.", "child", signer.FlagsKSK)
	signed, err := signer.SignZone(exampleZone(t, child), "example.test.", []*signer.Key{ksk}, signOpts())
	if err != nil {
		t.Fatal(err)
	}
	text, err := signed.PrintCanonical(0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "INVALID") || strings.Contains(text, "UNALLOC") {
		t.Errorf("unexpected mnemonic in output:\n%s", text)
	}
}
