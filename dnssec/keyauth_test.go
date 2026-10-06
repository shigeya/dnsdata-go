package dnssec_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// kskFixture is a child zone with a KSK (authenticated by a DS record in
// its parent) signing the DNSKEY rrset, and a ZSK signing www/A.
type kskFixture struct {
	z, parent         *dnssec.Zone
	ksk, zsk          *dnssec.DNSKey
	apex              string
	inception, expire int64
}

// newKSKFixture builds the fixture. kskFlags are the KSK's DNSKEY
// flags. When collide is set, a key with the KSK's key tag and
// algorithm (but different key material, matching no DS) is placed in
// the DNSKEY rrset ahead of the KSK.
func newKSKFixture(t *testing.T, kskFlags uint16, collide bool) *kskFixture {
	t.Helper()
	f := &kskFixture{
		z:         dnssec.NewZone(),
		parent:    dnssec.NewZone(),
		apex:      "auth.example.",
		inception: time.Now().Add(-1 * time.Hour).Unix(),
		expire:    time.Now().Add(24 * time.Hour).Unix(),
	}
	kskPriv, kskValue := genECDSAKey(t, kskFlags)
	zskPriv, zskValue := genECDSAKey(t, 256)
	if collide {
		f.addKey(t, collidingKeyValue(t, kskValue))
	}
	f.ksk = f.addKey(t, kskValue)
	f.ksk.SetPrivateKey(kskPriv)
	f.zsk = f.addKey(t, zskValue)
	f.zsk.SetPrivateKey(zskPriv)
	if collide && f.z.FindDNSKey(f.apex, f.ksk.KeyTag) == f.ksk {
		t.Fatal("colliding key does not shadow the KSK in FindDNSKey")
	}

	f.sign(t, f.apex, types.TypeDNSKEY, f.ksk)
	if _, err := f.z.AddRRFromParts("www."+f.apex, 300, "IN", "A", "192.0.2.50"); err != nil {
		t.Fatalf("AddRR(A): %v", err)
	}
	f.sign(t, "www."+f.apex, types.TypeA, f.zsk)

	dsInput, err := f.ksk.DSDigestData()
	if err != nil {
		t.Fatalf("DSDigestData: %v", err)
	}
	sum := sha256.Sum256(dsInput)
	ds := joinSpace(dec(f.ksk.KeyTag), dec(uint16(f.ksk.Algorithm)), "2", hex.EncodeToString(sum[:]))
	if _, err := f.parent.AddRRFromParts(f.apex, 3600, "IN", "DS", ds); err != nil {
		t.Fatalf("AddRR(DS): %v", err)
	}
	f.z.SetParent(f.parent)
	return f
}

func (f *kskFixture) addKey(t *testing.T, value string) *dnssec.DNSKey {
	t.Helper()
	rr, err := f.z.AddRRFromParts(f.apex, 3600, "IN", "DNSKEY", value)
	if err != nil {
		t.Fatalf("AddRR(DNSKEY): %v", err)
	}
	return rr.Handler().(*dnssec.DNSKey)
}

func (f *kskFixture) sign(t *testing.T, name string, qtype uint16, key *dnssec.DNSKey) {
	t.Helper()
	sig, err := f.z.SignRR(name, 300, qtype, key, f.inception, f.expire)
	if err != nil || sig == nil {
		t.Fatalf("SignRR(%s/%d): %v", name, qtype, err)
	}
	f.z.AddRR(sig)
}

// collidingKeyValue returns a DNSKEY presentation value with the same
// flags, algorithm and key tag as value but different key data: two
// distinct 16-bit words of the key are swapped, which leaves the RFC
// 4034 Appendix B checksum unchanged.
func collidingKeyValue(t *testing.T, value string) string {
	t.Helper()
	parts := strings.Fields(value)
	flags, proto, alg, b64 := parts[0], parts[1], parts[2], parts[3]
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i+1 < len(data); i += 2 {
		if data[0] != data[i] || data[1] != data[i+1] {
			data[0], data[1], data[i], data[i+1] = data[i], data[i+1], data[0], data[1]
			return joinSpace(flags, proto, alg, base64.StdEncoding.EncodeToString(data))
		}
	}
	t.Fatal("no two distinct words in key data")
	return ""
}

// statuses returns the status of every RRSIG over (name, qtype) by
// key tag.
func statuses(z *dnssec.Zone, name string, qtype uint16, mode dnssec.KeyVerifyMode) map[uint16]dnssec.SigStatus {
	out := map[uint16]dnssec.SigStatus{}
	for _, r := range z.CheckRRSet(name, qtype, mode, "") {
		out[r.RRSig.KeyTag] = r.Status
	}
	return out
}

func wantVerified(t *testing.T, z *dnssec.Zone, name string, qtype uint16, mode dnssec.KeyVerifyMode, want bool) {
	t.Helper()
	ok, err := z.VerifyRRSet(name, qtype, mode, "")
	if err != nil {
		t.Fatalf("VerifyRRSet(%s/%d, mode %d): %v", name, qtype, mode, err)
	}
	if ok != want {
		t.Errorf("VerifyRRSet(%s/%d, mode %d) = %v, want %v", name, qtype, mode, ok, want)
	}
}

// TestKSK_DSAuthenticated is the baseline: the DS-matched KSK signs the
// DNSKEY rrset, the ZSK in it signs data. The SEP flag plays no part.
func TestKSK_DSAuthenticated(t *testing.T) {
	for _, flags := range []uint16{257, 256} {
		f := newKSKFixture(t, flags, false)
		wantVerified(t, f.z, f.apex, types.TypeDNSKEY, dnssec.KeyModeKSK, true)
		wantVerified(t, f.z, "www."+f.apex, types.TypeA, dnssec.KeyModeZSK, true)
		wantVerified(t, f.z, "www."+f.apex, types.TypeA, dnssec.KeyModeCSK, true)
		// The ZSK is not a KSK: no DS names it.
		if got := statuses(f.z, "www."+f.apex, types.TypeA, dnssec.KeyModeKSK)[f.zsk.KeyTag]; got != dnssec.SigNoMatchingKey {
			t.Errorf("flags %d: ZSK signature in KSK mode = %s, want no-matching-key", flags, got)
		}
	}
}

// TestKSK_TamperedSignatureIsInvalid: the KSK being authenticated does
// not excuse its signature from being checked.
func TestKSK_TamperedSignatureIsInvalid(t *testing.T) {
	f := newKSKFixture(t, 257, false)
	sigs := f.z.FindRRSIGs(f.apex, types.TypeDNSKEY, "")
	if len(sigs) != 1 {
		t.Fatalf("%d DNSKEY RRSIGs, want 1", len(sigs))
	}
	sigs[0].Signature[0] ^= 0x01

	if got := statuses(f.z, f.apex, types.TypeDNSKEY, dnssec.KeyModeKSK)[f.ksk.KeyTag]; got != dnssec.SigInvalid {
		t.Errorf("tampered KSK signature = %s, want invalid", got)
	}
	wantVerified(t, f.z, f.apex, types.TypeDNSKEY, dnssec.KeyModeKSK, false)
	wantVerified(t, f.z, "www."+f.apex, types.TypeA, dnssec.KeyModeZSK, false)
}

// TestKSK_InjectedKeyIsNotAuthenticated: a key added to the DNSKEY
// rrset that signs the enlarged rrset (and data) itself is not a KSK,
// with or without the SEP flag; the real KSK's signature no longer
// covers the rrset.
func TestKSK_InjectedKeyIsNotAuthenticated(t *testing.T) {
	for _, flags := range []uint16{257, 256} {
		f := newKSKFixture(t, 257, false)
		priv, value := genECDSAKey(t, flags)
		evil := f.addKey(t, value)
		evil.SetPrivateKey(priv)
		f.sign(t, f.apex, types.TypeDNSKEY, evil)
		if _, err := f.z.AddRRFromParts("evil."+f.apex, 300, "IN", "A", "203.0.113.66"); err != nil {
			t.Fatal(err)
		}
		f.sign(t, "evil."+f.apex, types.TypeA, evil)

		got := statuses(f.z, f.apex, types.TypeDNSKEY, dnssec.KeyModeKSK)
		if got[evil.KeyTag] != dnssec.SigNoMatchingKey {
			t.Errorf("flags %d: injected key's signature = %s, want no-matching-key", flags, got[evil.KeyTag])
		}
		if got[f.ksk.KeyTag] != dnssec.SigInvalid {
			t.Errorf("flags %d: stale KSK signature = %s, want invalid", flags, got[f.ksk.KeyTag])
		}
		wantVerified(t, f.z, f.apex, types.TypeDNSKEY, dnssec.KeyModeKSK, false)
		for _, mode := range []dnssec.KeyVerifyMode{dnssec.KeyModeZSK, dnssec.KeyModeKSK, dnssec.KeyModeCSK} {
			wantVerified(t, f.z, "evil."+f.apex, types.TypeA, mode, false)
		}
	}
}

// TestKSK_KeyTagCollision: every DNSKEY with the RRSIG's signer, key tag
// and algorithm is tried, so a colliding key listed first does not
// shadow the real KSK.
func TestKSK_KeyTagCollision(t *testing.T) {
	f := newKSKFixture(t, 257, true)
	wantVerified(t, f.z, f.apex, types.TypeDNSKEY, dnssec.KeyModeKSK, true)
	wantVerified(t, f.z, "www."+f.apex, types.TypeA, dnssec.KeyModeZSK, true)
}
