package dnssec_test

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

func TestSigStatus_String(t *testing.T) {
	want := map[dnssec.SigStatus]string{
		dnssec.SigVerified:             "verified",
		dnssec.SigExpired:              "expired",
		dnssec.SigNotYetValid:          "not-yet-valid",
		dnssec.SigUnsupportedAlgorithm: "unsupported-algorithm",
		dnssec.SigNoMatchingKey:        "no-matching-key",
		dnssec.SigInvalid:              "invalid",
	}
	for s, w := range want {
		if s.String() != w {
			t.Errorf("%d.String() = %q, want %q", s, s.String(), w)
		}
	}
}

// TestZone_CheckRRSIG classifies one RRSIG over www.<label>/A, signed
// from now-1h to now+24h.
func TestZone_CheckRRSIG(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		prepare func(t *testing.T, z *dnssec.Zone, sig *dnssec.RRSig) *dnssec.RRSig
		want    dnssec.SigStatus
		wantErr error
	}{
		{"verified", keep, dnssec.SigVerified, nil},
		{"expired", clockAt(now.Add(48 * time.Hour)), dnssec.SigExpired, nil},
		{"not yet valid", clockAt(now.Add(-48 * time.Hour)), dnssec.SigNotYetValid, nil},
		{"no matching key", func(t *testing.T, _ *dnssec.Zone, sig *dnssec.RRSig) *dnssec.RRSig {
			c := sig.Clone().(*dnssec.RRSig)
			c.KeyTag++
			return c
		}, dnssec.SigNoMatchingKey, nil},
		{"invalid", func(t *testing.T, _ *dnssec.Zone, sig *dnssec.RRSig) *dnssec.RRSig {
			c := sig.Clone().(*dnssec.RRSig)
			c.Signature[0] ^= 0x01
			return c
		}, dnssec.SigInvalid, nil},
		{"unsupported algorithm", unsupportedKey, dnssec.SigUnsupportedAlgorithm, dnssec.ErrUnsupportedAlgorithm},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			z, _ := signZone(t, "check.example.")
			z.SetClock(func() time.Time { return now })
			sigs := z.FindRRSIGs("www.check.example.", types.TypeA, "")
			if len(sigs) != 1 {
				t.Fatalf("%d RRSIGs, want 1", len(sigs))
			}
			sig := c.prepare(t, z, sigs[0])

			got, err := z.CheckRRSIG("www.check.example.", types.TypeA, sig, dnssec.KeyModeNone)
			if got != c.want {
				t.Errorf("status %s, want %s", got, c.want)
			}
			if !errors.Is(err, c.wantErr) || (c.wantErr == nil) != (err == nil) {
				t.Errorf("err %v, want %v", err, c.wantErr)
			}
			ok, verr := z.VerifyRRSIG("www.check.example.", types.TypeA, sig, dnssec.KeyModeNone)
			if ok != (c.want == dnssec.SigVerified) || (verr == nil) != (err == nil) {
				t.Errorf("VerifyRRSIG = %v, %v; disagrees with CheckRRSIG", ok, verr)
			}
		})
	}
}

func keep(_ *testing.T, _ *dnssec.Zone, sig *dnssec.RRSig) *dnssec.RRSig { return sig }

func clockAt(at time.Time) func(*testing.T, *dnssec.Zone, *dnssec.RRSig) *dnssec.RRSig {
	return func(_ *testing.T, z *dnssec.Zone, sig *dnssec.RRSig) *dnssec.RRSig {
		z.SetClock(func() time.Time { return at })
		return sig
	}
}

// unsupportedKey adds a DNSKEY of algorithm 16 (Ed448, not implemented)
// to the zone and returns an RRSIG naming it.
func unsupportedKey(t *testing.T, z *dnssec.Zone, sig *dnssec.RRSig) *dnssec.RRSig {
	t.Helper()
	keyData := make([]byte, 57)
	if _, err := rand.Read(keyData); err != nil {
		t.Fatal(err)
	}
	rr, err := z.AddRRFromParts(sig.Signer, 3600, "IN", "DNSKEY", "256 3 16 "+base64.StdEncoding.EncodeToString(keyData))
	if err != nil {
		t.Fatal(err)
	}
	key, ok := z.Handler(rr).(*dnssec.DNSKey)
	if !ok {
		t.Fatalf("DNSKEY handler %T", z.Handler(rr))
	}
	c := sig.Clone().(*dnssec.RRSig)
	c.Algorithm, c.KeyTag = 16, key.KeyTag
	return c
}

// TestZone_CheckRRSet lists every RRSIG over the rrset with its status,
// and agrees with VerifyRRSet.
func TestZone_CheckRRSet(t *testing.T) {
	now := time.Now()
	z, key := signZone(t, "set.example.")
	z.SetClock(func() time.Time { return now })
	// A second, expired signature by the same key.
	old, err := z.SignRR("www.set.example.", 300, types.TypeA, key,
		now.Add(-72*time.Hour).Unix(), now.Add(-48*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	z.AddRR(old)

	results := z.CheckRRSet("www.set.example.", types.TypeA, dnssec.KeyModeNone, "")
	got := map[dnssec.SigStatus]int{}
	for _, r := range results {
		if r.RRSig == nil {
			t.Fatal("result without its RRSIG")
		}
		got[r.Status]++
	}
	if fmt.Sprint(got) != fmt.Sprint(map[dnssec.SigStatus]int{dnssec.SigVerified: 1, dnssec.SigExpired: 1}) {
		t.Errorf("statuses %v, want one verified and one expired", got)
	}
	ok, err := dnssec.RRSetVerified(results)
	if !ok || err != nil {
		t.Errorf("RRSetVerified = %v, %v; want true", ok, err)
	}
	if ok2, _ := z.VerifyRRSet("www.set.example.", types.TypeA, dnssec.KeyModeNone, ""); !ok2 {
		t.Error("VerifyRRSet disagrees")
	}
}
