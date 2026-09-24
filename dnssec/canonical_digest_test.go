package dnssec_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

const testRRType uint16 = 65400

func digestFor(t *testing.T, z *dnssec.Zone) []byte {
	t.Helper()
	sig := &dnssec.RRSig{TypeCovered: testRRType, Algorithm: 13, Labels: 2, OriginalTTL: 60, Signer: "example."}
	dt, err := z.CreateDigestTarget(sig, "x.example.", testRRType)
	if err != nil || dt == nil {
		t.Fatalf("CreateDigestTarget: %x, %v", dt, err)
	}
	return dt
}

// RFC 4034 §6.3: RRs are ordered by RDATA alone. With the RDLENGTH
// prefix included, the shorter "b" would wrongly sort before "ab".
func TestCreateDigestTarget_OrdersByRDataOnly(t *testing.T) {
	z := dnssec.NewZone()
	for _, v := range []string{`\# 1 62`, `\# 2 6162`} {
		if _, err := z.AddRRFromParts("x.example.", 60, "IN", "TYPE65400", v); err != nil {
			t.Fatal(err)
		}
	}
	dt := digestFor(t, z)
	ab := bytes.Index(dt, []byte{0x00, 0x02, 0x61, 0x62})
	b := bytes.Index(dt, []byte{0x00, 0x01, 0x62})
	if ab < 0 || b < 0 || ab > b {
		t.Errorf("RDATA \"ab\" at %d, \"b\" at %d; want \"ab\" first (digest %x)", ab, b, dt)
	}
}

// RFC 4034 §6.3: duplicate RRs are removed before signing / verifying.
func TestCreateDigestTarget_DropsDuplicates(t *testing.T) {
	single, double := dnssec.NewZone(), dnssec.NewZone()
	for _, z := range []*dnssec.Zone{single, double, double} {
		if _, err := z.AddRRFromParts("x.example.", 60, "IN", "TYPE65400", `\# 1 62`); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(digestFor(t, single), digestFor(t, double)) {
		t.Error("a duplicated RR changed the digest target")
	}
}

func TestVerifyRRSet_ValidityWindow(t *testing.T) {
	dnssec.RegisterHandlers()
	inception := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expire := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	z := dnssec.NewZone()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pub := uncompressed[1:] // drop the 0x04 prefix: RFC 6605 key field is X || Y
	keyRR, err := z.AddRRFromParts("example.", 60, "IN", "DNSKEY", "257 3 13 "+base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatal(err)
	}
	key := keyRR.Handler().(*dnssec.DNSKey)
	key.SetPrivateKey(priv)
	if _, err := z.AddRRFromParts("x.example.", 60, "IN", "A", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	sig, err := z.SignRR("x.example.", 60, types.TypeA, key, inception.Unix(), expire.Unix())
	if err != nil || sig == nil {
		t.Fatalf("SignRR: %v", err)
	}
	z.AddRR(sig)

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"inside", inception.Add(24 * time.Hour), true},
		{"at inception", inception, true},
		{"at expiration", expire, true},
		{"before inception", inception.Add(-time.Second), false},
		{"after expiration", expire.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z.SetClock(func() time.Time { return tc.now })
			ok, err := z.VerifyRRSet("x.example.", types.TypeA, dnssec.KeyModeNone, "")
			if err != nil || ok != tc.want {
				t.Errorf("VerifyRRSet = %v, %v; want %v", ok, err, tc.want)
			}
		})
	}

	z.SetClock(nil)
	if ok, _ := z.VerifyRRSet("x.example.", types.TypeA, dnssec.KeyModeNone, ""); !ok {
		t.Error("without a clock the window is not checked (existing behaviour)")
	}
}
