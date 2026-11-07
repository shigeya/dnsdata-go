package zone_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// OPKEY RDATA (draft-shigeya-dns-opkey-00) shares the TLSA codec. The
// type value is not allocated, so the transitional form (a TLSA RRset)
// and RFC 3597 generic RDATA under a test-local type number are the
// only ways it appears here. No test uses a private-use type value.

const (
	// Example of draft §2.3 and its generic form of draft §4.2.
	opkeyDraftHex     = "c9d1a2f0e3b45c67d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5"
	opkeyDraftValue   = "3 1 1 " + opkeyDraftHex
	opkeyDraftGeneric = `\# 35 030101` + opkeyDraftHex

	// testOPKEYType is a test-local type number for the RFC 3597 case:
	// unassigned, and outside the private-use range.
	testOPKEYType uint16 = 4242
)

// testSPKI returns the DER SubjectPublicKeyInfo of a deterministic
// Ed25519 key.
func testSPKI(t *testing.T, seed byte) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

func mustOPKEYForSPKI(t *testing.T, matchingType uint8, spki []byte) zone.OPKEY {
	t.Helper()
	k, err := zone.NewOPKEYForSPKI(matchingType, spki)
	if err != nil {
		t.Fatalf("NewOPKEYForSPKI(%d): %v", matchingType, err)
	}
	return k
}

func mustParseOPKEY(t *testing.T, value string) zone.OPKEY {
	t.Helper()
	k, err := zone.ParseOPKEY(value)
	if err != nil {
		t.Fatalf("ParseOPKEY(%q): %v", value, err)
	}
	return k
}

func equalOPKEY(a, b zone.OPKEY) bool {
	return a.Usage == b.Usage && a.Selector == b.Selector && a.MatchingType == b.MatchingType &&
		bytes.Equal(a.CertificateAssociationData, b.CertificateAssociationData)
}

func assertOPKEYs(t *testing.T, got, want []zone.OPKEY) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !equalOPKEY(got[i], want[i]) {
			t.Errorf("record %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// --- §7.1 round trip --------------------------------------------------

func TestOPKEY_DraftExampleRoundTrip(t *testing.T) {
	k := mustParseOPKEY(t, opkeyDraftValue)
	if !k.Usable() {
		t.Errorf("draft example not usable: %v", k.Check())
	}
	if got := k.String(); got != opkeyDraftValue {
		t.Errorf("String() = %q, want %q", got, opkeyDraftValue)
	}
	wantRData, _ := hex.DecodeString("030101" + opkeyDraftHex)
	if got := k.RData(); !bytes.Equal(got, wantRData) {
		t.Errorf("RData() = %x, want %x", got, wantRData)
	}
	decoded, err := zone.DecodeOPKEYRData(k.RData())
	if err != nil || !equalOPKEY(decoded, k) {
		t.Errorf("DecodeOPKEYRData(RData()) = %v, %v; want %v", decoded, err, k)
	}
	if got := mustParseOPKEY(t, opkeyDraftGeneric); !equalOPKEY(got, k) {
		t.Errorf("generic form parsed to %v, want %v", got, k)
	}
	if got := wire.FormatGenericRData(k.RData()); got != opkeyDraftGeneric {
		t.Errorf("generic form = %q, want %q", got, opkeyDraftGeneric)
	}
}

func TestOPKEY_RoundTripBothMatchingTypes(t *testing.T) {
	spki := testSPKI(t, 1)
	for _, mt := range []uint8{zone.OPKEYMatchingSHA256, zone.OPKEYMatchingSHA512} {
		k := mustOPKEYForSPKI(t, mt, spki)
		if got := mustParseOPKEY(t, k.String()); !equalOPKEY(got, k) {
			t.Errorf("mt %d: presentation round trip = %v, want %v", mt, got, k)
		}
		decoded, err := zone.DecodeOPKEYRData(k.RData())
		if err != nil || !equalOPKEY(decoded, k) {
			t.Errorf("mt %d: wire round trip = %v, %v; want %v", mt, decoded, err, k)
		}
	}
}

// --- §7.2 presentation format -----------------------------------------

func TestParseOPKEY_PresentationVariants(t *testing.T) {
	want := mustParseOPKEY(t, opkeyDraftValue)
	for _, v := range []string{
		"3 1 1 " + strings.ToUpper(opkeyDraftHex),
		"3  1\t1 c9d1a2f0e3b45c67d8e9f0a1b2c3d4e5 F60718293A4B5C6D7E8F90A1B2C3D4E5",
	} {
		got := mustParseOPKEY(t, v)
		if !equalOPKEY(got, want) {
			t.Errorf("ParseOPKEY(%q) = %v, want %v", v, got, want)
		}
		if s := got.String(); s != opkeyDraftValue {
			t.Errorf("String() after %q = %q, want lower-case %q", v, s, opkeyDraftValue)
		}
	}
}

func TestOPKEYFromTLSA_ZoneTextInParentheses(t *testing.T) {
	const text = `
$ORIGIN example.
$TTL 3600
_issuer-key._op IN TLSA 3 1 1 (
    C9D1A2F0E3B45C67D8E9F0A1B2C3D4E5 ; upper case
    f60718293a4b5c6d7e8f90a1b2c3d4e5 )
`
	for name, read := range map[string]func(*zone.Zone, string) error{
		"strict": (*zone.Zone).ReadStringStrict,
		"lax":    (*zone.Zone).ReadString,
	} {
		var z zone.Zone
		if err := read(&z, text); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := zone.OPKEYFromTLSA(z.FindRRSet("_issuer-key._op.example.", types.TypeTLSA))
		if err != nil {
			t.Fatalf("%s: OPKEYFromTLSA: %v", name, err)
		}
		assertOPKEYs(t, got, []zone.OPKEY{mustParseOPKEY(t, opkeyDraftValue)})
	}
}

// --- §7.3 values outside the restrictions -------------------------------

type outsideRestrictionCase struct {
	name                   string
	usage, selector, match uint8
	data                   []byte
}

// outsideRestrictionCases are records listing spki that the draft does
// not permit: each must parse and be unusable.
func outsideRestrictionCases(spki []byte) []outsideRestrictionCase {
	d256 := sha256.Sum256(spki)
	d512 := sha512.Sum512(spki)
	return []outsideRestrictionCase{
		{"usage 0", 0, 1, 1, d256[:]},
		{"usage 1", 1, 1, 1, d256[:]},
		{"usage 2", 2, 1, 1, d256[:]},
		{"selector 0", 3, 0, 1, d256[:]},
		{"matching type 0", 3, 1, 0, spki},
		{"matching type 3", 3, 1, 3, d256[:]},
		{"SHA-256 with 31 octets", 3, 1, 1, d256[:31]},
		{"SHA-256 with 64 octets", 3, 1, 1, d512[:]},
		{"SHA-512 with 32 octets", 3, 1, 2, d256[:]},
	}
}

func TestOPKEY_OutsideRestrictionsParseButUnusable(t *testing.T) {
	spki := testSPKI(t, 1)
	var all []zone.OPKEY
	for _, c := range outsideRestrictionCases(spki) {
		k := mustParseOPKEY(t, fmt.Sprintf("%d %d %d %x", c.usage, c.selector, c.match, c.data))
		if k.Usable() {
			t.Errorf("%s: Usable() = true", c.name)
		}
		if err := k.Check(); !errors.Is(err, zone.ErrRDataFormat) {
			t.Errorf("%s: Check() = %v, want ErrRDataFormat", c.name, err)
		}
		all = append(all, k)
	}
	for _, sup := range [][]uint8{nil, {1}, {2}} {
		ok, err := zone.MatchOPKEYSPKI(spki, all, sup...)
		if ok || err != nil {
			t.Errorf("supported %v: MatchOPKEYSPKI over unusable records = %v, %v; want false, nil", sup, ok, err)
		}
	}
}

func TestNewOPKEY_RejectsWhatTheDraftForbids(t *testing.T) {
	d := sha256.Sum256([]byte("x"))
	for _, c := range []struct {
		name   string
		match  uint8
		digest []byte
	}{
		{"matching type 0", 0, d[:]},
		{"matching type 3", 3, d[:]},
		{"SHA-256 with 31 octets", 1, d[:31]},
		{"SHA-512 with 32 octets", 2, d[:]},
		{"empty digest", 1, nil},
	} {
		if _, err := zone.NewOPKEY(c.match, c.digest); !errors.Is(err, zone.ErrRDataFormat) {
			t.Errorf("%s: NewOPKEY err = %v, want ErrRDataFormat", c.name, err)
		}
	}
	if _, err := zone.NewOPKEYForSPKI(0, []byte{1}); !errors.Is(err, zone.ErrRDataFormat) {
		t.Errorf("NewOPKEYForSPKI(0) err = %v, want ErrRDataFormat", err)
	}
	if _, err := zone.NewOPKEYForSPKI(1, nil); !errors.Is(err, zone.ErrRDataFormat) {
		t.Errorf("NewOPKEYForSPKI(empty SPKI) err = %v, want ErrRDataFormat", err)
	}
}

func TestNewOPKEY_FixesUsageSelectorAndCopiesDigest(t *testing.T) {
	d := sha256.Sum256([]byte("x"))
	digest := d[:]
	k, err := zone.NewOPKEY(zone.OPKEYMatchingSHA256, digest)
	if err != nil {
		t.Fatalf("NewOPKEY: %v", err)
	}
	if k.Usage != 3 || k.Selector != 1 || !k.Usable() {
		t.Errorf("NewOPKEY = %v, want usage 3, selector 1, usable", k)
	}
	digest[0] ^= 0xff
	if k.CertificateAssociationData[0] == digest[0] {
		t.Error("NewOPKEY shares the caller's digest slice")
	}
}

func TestDecodeOPKEYRData_Short(t *testing.T) {
	if _, err := zone.DecodeOPKEYRData([]byte{3, 1}); !errors.Is(err, zone.ErrRDataFormat) {
		t.Errorf("2 octets: err = %v, want ErrRDataFormat", err)
	}
	k, err := zone.DecodeOPKEYRData([]byte{3, 1, 1})
	if err != nil {
		t.Fatalf("3 octets: %v", err)
	}
	if k.Usable() {
		t.Error("3 octets: Usable() = true")
	}
	if got := k.String(); got != `\# 3 030101` {
		t.Errorf("3 octets: String() = %q, want the generic form", got)
	}
}

// --- §7.4 matching ------------------------------------------------------

func TestMatchOPKEYSPKI(t *testing.T) {
	keyA, keyB := testSPKI(t, 1), testSPKI(t, 2)
	a256, a512 := mustOPKEYForSPKI(t, 1, keyA), mustOPKEYForSPKI(t, 2, keyA)
	b256, b512 := mustOPKEYForSPKI(t, 1, keyB), mustOPKEYForSPKI(t, 2, keyB)
	brokenSHA512 := zone.OPKEY{Usage: 3, Selector: 1, MatchingType: 2, CertificateAssociationData: []byte{1}}

	for _, c := range []struct {
		name      string
		keys      []zone.OPKEY
		supported []uint8
		want      bool
	}{
		{"SHA-256 only", []zone.OPKEY{a256}, nil, true},
		{"SHA-512 only", []zone.OPKEY{a512}, nil, true},
		{"both, listed in both", []zone.OPKEY{a256, a512}, nil, true},
		{"SHA-512 selected, key listed only by SHA-256", []zone.OPKEY{a256, b512}, nil, false},
		{"caller supports only SHA-256", []zone.OPKEY{a256, b512}, []uint8{1}, true},
		{"caller supports only SHA-512, RRset has SHA-256 only", []zone.OPKEY{a256}, []uint8{2}, false},
		{"other key only", []zone.OPKEY{b256, b512}, nil, false},
		{"unusable SHA-512 does not take part in selection", []zone.OPKEY{a256, brokenSHA512}, nil, true},
		{"empty RRset", nil, nil, false},
	} {
		got, err := zone.MatchOPKEYSPKI(keyA, c.keys, c.supported...)
		if err != nil || got != c.want {
			t.Errorf("%s: MatchOPKEYSPKI = %v, %v; want %v, nil", c.name, got, err, c.want)
		}
	}
}

func TestMatchOPKEYSPKI_InvalidArguments(t *testing.T) {
	keys := []zone.OPKEY{mustOPKEYForSPKI(t, 1, testSPKI(t, 1))}
	if _, err := zone.MatchOPKEYSPKI(nil, keys); !errors.Is(err, zone.ErrOPKEYMatch) {
		t.Errorf("empty SPKI: err = %v, want ErrOPKEYMatch", err)
	}
	for _, mt := range []uint8{0, 3} {
		if _, err := zone.MatchOPKEYSPKI(testSPKI(t, 1), keys, mt); !errors.Is(err, zone.ErrOPKEYMatch) {
			t.Errorf("supported %d: err = %v, want ErrOPKEYMatch", mt, err)
		}
	}
}

// --- §7.5 TLSA unchanged ------------------------------------------------

func TestTLSA_OutsideOPKEYRestrictionsStillRoundTrips(t *testing.T) {
	const value = "0 0 0 aabbcc"
	rr := newRR(t, "_443._tcp.example.com.", 3600, "IN", "TLSA", value)
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	want := []byte{0, 6, 0, 0, 0, 0xaa, 0xbb, 0xcc}
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("WireBody = %x, want %x", b.Bytes(), want)
	}
	rdata := b.Bytes()[2:]
	got, err := wire.RDataToString(rdata, types.TypeTLSA, rdata, 0)
	if err != nil || got != value {
		t.Errorf("RDataToString = %q, %v; want %q", got, err, value)
	}
}

// --- §7.6 transitional reading -------------------------------------------

func TestOPKEYFromTLSA_AllForms(t *testing.T) {
	const owner = "_issuer-key._op.example."
	a256 := mustOPKEYForSPKI(t, 1, testSPKI(t, 1))
	b512 := mustOPKEYForSPKI(t, 2, testSPKI(t, 2))

	var rrs []*zone.ResourceRecord
	for _, k := range []zone.OPKEY{a256, b512} {
		rdata := k.RData()
		pres, err := wire.RDataToString(rdata, types.TypeTLSA, rdata, 0)
		if err != nil {
			t.Fatalf("RDataToString: %v", err)
		}
		received, err := zone.NewResourceRecordWithRData(owner, 3600, "IN", "TLSA", pres, rdata)
		if err != nil {
			t.Fatalf("NewResourceRecordWithRData: %v", err)
		}
		generic, err := zone.NewResourceRecordFromRData(owner, 3600, types.ClassIN, types.TypeTLSA, rdata)
		if err != nil {
			t.Fatalf("NewResourceRecordFromRData: %v", err)
		}
		rrs = append(rrs, received, generic)
	}
	got, err := zone.OPKEYFromTLSA(rrs)
	if err != nil {
		t.Fatalf("OPKEYFromTLSA: %v", err)
	}
	assertOPKEYs(t, got, []zone.OPKEY{a256, a256, b512, b512})
}

func TestOPKEYFromTLSA_DoesNotFilter(t *testing.T) {
	rrs := []*zone.ResourceRecord{
		newRR(t, "x.example.", 3600, "IN", "TLSA", "0 0 0 aabb"),
		newRR(t, "x.example.", 3600, "IN", "TLSA", opkeyDraftValue),
	}
	got, err := zone.OPKEYFromTLSA(rrs)
	if err != nil {
		t.Fatalf("OPKEYFromTLSA: %v", err)
	}
	if len(got) != 2 || got[0].Usable() || !got[1].Usable() {
		t.Errorf("OPKEYFromTLSA = %v, want both records, only the second usable", got)
	}
}

func TestOPKEYFromTLSA_Errors(t *testing.T) {
	for name, rr := range map[string]*zone.ResourceRecord{
		"not TLSA":  newRR(t, "x.example.", 3600, "IN", "TXT", `"3 1 1 aabb"`),
		"malformed": newRR(t, "x.example.", 3600, "IN", "TLSA", "3 1 1 zz"),
		"short":     newRR(t, "x.example.", 3600, "IN", "TLSA", `\# 2 0301`),
		"nil":       nil,
	} {
		if _, err := zone.OPKEYFromTLSA([]*zone.ResourceRecord{rr}); err == nil {
			t.Errorf("%s: OPKEYFromTLSA err = nil", name)
		}
	}
}

// --- §7.7 unknown type (RFC 3597) ---------------------------------------

func TestDecodeOPKEYRData_GenericUnderTestLocalType(t *testing.T) {
	text := fmt.Sprintf("$TTL 3600\nk.example. IN TYPE%d %s\n", testOPKEYType, opkeyDraftGeneric)
	var z zone.Zone
	if err := z.ReadStringStrict(text); err != nil {
		t.Fatalf("ReadStringStrict: %v", err)
	}
	rr := z.FindRR("k.example.", testOPKEYType)
	if rr == nil {
		t.Fatal("TYPE record missing")
	}
	raw, isGeneric, err := rr.GenericRData()
	if err != nil || !isGeneric {
		t.Fatalf("GenericRData = %v, %v", isGeneric, err)
	}
	got, err := zone.DecodeOPKEYRData(raw)
	if err != nil {
		t.Fatalf("DecodeOPKEYRData: %v", err)
	}
	if want := mustParseOPKEY(t, opkeyDraftValue); !equalOPKEY(got, want) {
		t.Errorf("generic RDATA decoded to %v, want the TLSA form %v", got, want)
	}
}

// --- §7.8 unallocated type ------------------------------------------------

func TestOPKEYMnemonic_UnallocatedInZoneText(t *testing.T) {
	text := "$TTL 3600\nk.example. IN OPKEY " + opkeyDraftValue + "\n"
	var strict zone.Zone
	err := strict.ReadStringStrict(text)
	var pe *zone.ParseError
	if !errors.As(err, &pe) || !errors.Is(err, types.ErrOPKEYTypeUnallocated) {
		t.Errorf("ReadStringStrict err = %v, want a ParseError wrapping ErrOPKEYTypeUnallocated", err)
	}
	if _, err := zone.NewResourceRecord("k.example.", 3600, "IN", "OPKEY", opkeyDraftValue); !errors.Is(err, types.ErrOPKEYTypeUnallocated) {
		t.Errorf("NewResourceRecord(OPKEY) err = %v, want ErrOPKEYTypeUnallocated", err)
	}
	var lax zone.Zone
	if err := lax.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got := lax.AllRecords(); len(got) != 0 {
		t.Errorf("ReadString kept %d records for the unallocated mnemonic, want 0", len(got))
	}
}
