package signer_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// fixedScalar is a deterministic P-256 private scalar for tests.
func fixedScalar(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

func bindPrivateECDSA(seed string) []byte {
	return []byte("Private-key-format: v1.3\n" +
		"Algorithm: 13 (ECDSAP256SHA256)\n" +
		"PrivateKey: " + base64.StdEncoding.EncodeToString(fixedScalar(seed)) + "\n" +
		"Created: 20260101000000\n")
}

func TestGenerateKey_Algorithms(t *testing.T) {
	for _, alg := range []uint8{types.AlgoECDSAP256SHA256, types.AlgoECDSAP384SHA384, types.AlgoED25519, types.AlgoRSASHA256} {
		t.Run(fmt.Sprint(alg), func(t *testing.T) {
			k, err := signer.GenerateKey("example.test.", alg, signer.FlagsKSK)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			parsed, err := dnssec.ParseDNSKey(nil, k.DNSKEYValue())
			if err != nil {
				t.Fatalf("DNSKEYValue %q does not parse: %v", k.DNSKEYValue(), err)
			}
			if parsed.KeyTag != k.KeyTag() || parsed.Algorithm != alg || parsed.Flags != signer.FlagsKSK {
				t.Errorf("parsed = tag %d alg %d flags %d; key tag %d", parsed.KeyTag, parsed.Algorithm, parsed.Flags, k.KeyTag())
			}
			if _, err := parsed.PublicKey(); err != nil {
				t.Errorf("public key field does not decode: %v", err)
			}
			if !k.IsKSK() {
				t.Error("IsKSK = false for flags 257")
			}
		})
	}
	if _, err := signer.GenerateKey("example.test.", types.AlgoRSASHA1, signer.FlagsZSK); !errors.Is(err, signer.ErrUnsupportedAlgorithm) {
		t.Errorf("GenerateKey(RSASHA1) err = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := signer.GenerateKey("example.test", types.AlgoED25519, signer.FlagsZSK); err == nil {
		t.Error("GenerateKey with a relative owner: want error")
	}
}

func TestPKCS8PEM_RoundTrip(t *testing.T) {
	for _, alg := range []uint8{types.AlgoECDSAP256SHA256, types.AlgoED25519, types.AlgoRSASHA256} {
		k, err := signer.GenerateKey("example.test.", alg, signer.FlagsZSK)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes, err := k.PKCS8PEM()
		if err != nil {
			t.Fatalf("PKCS8PEM: %v", err)
		}
		back, err := signer.ParsePKCS8PEM("example.test.", signer.FlagsZSK, alg, pemBytes)
		if err != nil {
			t.Fatalf("ParsePKCS8PEM: %v", err)
		}
		if back.DNSKEYValue() != k.DNSKEYValue() {
			t.Errorf("alg %d: round trip changed the key", alg)
		}
	}
}

func TestParsePKCS8PEM_InfersAlgorithm(t *testing.T) {
	k, _ := signer.GenerateKey("example.test.", types.AlgoED25519, signer.FlagsKSK)
	pemBytes, _ := k.PKCS8PEM()
	back, err := signer.ParsePKCS8PEM("example.test.", signer.FlagsKSK, 0, pemBytes)
	if err != nil || back.Algorithm != types.AlgoED25519 {
		t.Fatalf("inferred algorithm = %v, %v", back, err)
	}
	if _, err := signer.ParsePKCS8PEM("example.test.", signer.FlagsKSK, types.AlgoECDSAP256SHA256, pemBytes); err == nil {
		t.Error("Ed25519 key declared as ECDSA: want error")
	}
	if _, err := signer.ParsePKCS8PEM("example.test.", signer.FlagsKSK, 0, []byte("not pem")); err == nil {
		t.Error("garbage: want error")
	}
}

func TestParseBINDPrivate_ECDSAIsDeterministic(t *testing.T) {
	a, err := signer.ParseBINDPrivate("example.test.", signer.FlagsKSK, bindPrivateECDSA("k1"))
	if err != nil {
		t.Fatalf("ParseBINDPrivate: %v", err)
	}
	b, _ := signer.ParseBINDPrivate("example.test.", signer.FlagsKSK, bindPrivateECDSA("k1"))
	if a.DNSKEYValue() != b.DNSKEYValue() || a.KeyTag() != b.KeyTag() {
		t.Error("same private key produced different DNSKEYs")
	}
	c, _ := signer.ParseBINDPrivate("example.test.", signer.FlagsKSK, bindPrivateECDSA("k2"))
	if a.DNSKEYValue() == c.DNSKEYValue() {
		t.Error("different private keys produced the same DNSKEY")
	}
}

func TestParseBINDPrivate_Errors(t *testing.T) {
	cases := map[string]string{
		"no algorithm":  "Private-key-format: v1.3\nPrivateKey: AAAA\n",
		"unsupported":   "Algorithm: 3 (DSA)\nPrivateKey: AAAA\n",
		"missing field": "Algorithm: 13 (ECDSAP256SHA256)\n",
		"bad base64":    "Algorithm: 15 (ED25519)\nPrivateKey: !!!\n",
		"short ed25519": "Algorithm: 15 (ED25519)\nPrivateKey: AAAA\n",
		"rsa missing":   "Algorithm: 8 (RSASHA256)\nModulus: AQAB\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := signer.ParseBINDPrivate("example.test.", signer.FlagsKSK, []byte(text)); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestDS_VerifiesAgainstDNSKEY(t *testing.T) {
	k, err := signer.ParseBINDPrivate("example.test.", signer.FlagsKSK, bindPrivateECDSA("ds"))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := zone.NewResourceRecord("example.test.", 3600, "IN", "DNSKEY", k.DNSKEYValue())
	if err != nil {
		t.Fatal(err)
	}
	dnskey, err := dnssec.ParseDNSKey(rr, k.DNSKEYValue())
	if err != nil {
		t.Fatal(err)
	}
	digestData, err := dnskey.DSDigestData()
	if err != nil {
		t.Fatal(err)
	}
	for _, dt := range []uint8{2, 4} {
		value, err := k.DS(dt)
		if err != nil {
			t.Fatalf("DS(%d): %v", dt, err)
		}
		ds, err := dnssec.ParseDS(nil, value)
		if err != nil {
			t.Fatalf("DS(%d) value %q does not parse: %v", dt, value, err)
		}
		if ok, err := ds.VerifyDigest(digestData); err != nil || !ok {
			t.Errorf("DS(%d) does not match its DNSKEY: %v", dt, err)
		}
		anchor, err := k.AnchorDS(dt)
		if err != nil {
			t.Fatal(err)
		}
		if anchor.KeyTag != k.KeyTag() || anchor.DigestType != dt ||
			!strings.EqualFold(anchor.Digest, hex.EncodeToString(ds.Digest)) || anchor.Digest != strings.ToUpper(anchor.Digest) {
			t.Errorf("AnchorDS(%d) = %+v", dt, anchor)
		}
	}
	if _, err := k.DS(1); err == nil {
		t.Error("DS(1): SHA-1 digests are not produced; want error")
	}
}

func TestRootAnchors(t *testing.T) {
	ksk, _ := signer.GenerateKey(".", types.AlgoECDSAP256SHA256, signer.FlagsKSK)
	zsk, _ := signer.GenerateKey(".", types.AlgoECDSAP256SHA256, signer.FlagsZSK)
	anchors, err := signer.RootAnchors(ksk, zsk)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors.DS) != 1 || anchors.DS[0].KeyTag != ksk.KeyTag() || anchors.DS[0].DigestType != 2 {
		t.Errorf("RootAnchors = %+v, want one SHA-256 DS for the KSK", anchors.DS)
	}
	notRoot, _ := signer.GenerateKey("test.", types.AlgoECDSAP256SHA256, signer.FlagsKSK)
	if _, err := signer.RootAnchors(notRoot); err == nil {
		t.Error("RootAnchors with a non-root key: want error")
	}
}

// Cross-check against BIND when its tools are installed: a key made by
// dnssec-keygen loads through ParseBINDPrivate to the same DNSKEY and DS.
func TestParseBINDPrivate_MatchesDNSSECKeygen(t *testing.T) {
	keygen, err := exec.LookPath("dnssec-keygen")
	if err != nil {
		t.Skip("dnssec-keygen not installed")
	}
	dsfromkey, err := exec.LookPath("dnssec-dsfromkey")
	if err != nil {
		t.Skip("dnssec-dsfromkey not installed")
	}
	for _, alg := range []string{"ECDSAP256SHA256", "ED25519", "RSASHA256"} {
		t.Run(alg, func(t *testing.T) {
			dir := t.TempDir()
			out, err := exec.Command(keygen, "-q", "-K", dir, "-a", alg, "-f", "KSK", "example.test").Output()
			if err != nil {
				t.Fatalf("dnssec-keygen: %v", err)
			}
			base := filepath.Join(dir, strings.TrimSpace(string(out)))
			priv, err := os.ReadFile(base + ".private")
			if err != nil {
				t.Fatal(err)
			}
			pub, err := os.ReadFile(base + ".key")
			if err != nil {
				t.Fatal(err)
			}
			k, err := signer.ParseBINDPrivate("example.test.", signer.FlagsKSK, priv)
			if err != nil {
				t.Fatalf("ParseBINDPrivate: %v", err)
			}
			if !strings.Contains(stripBlanks(string(pub)), stripBlanks(k.DNSKEYValue())) {
				t.Errorf("DNSKEY mismatch:\nBIND: %s\nours: %s", pub, k.DNSKEYValue())
			}
			dsOut, err := exec.Command(dsfromkey, "-2", base+".key").Output()
			if err != nil {
				t.Fatalf("dnssec-dsfromkey: %v", err)
			}
			ours, _ := k.DS(2)
			if !strings.Contains(strings.ToUpper(stripBlanks(string(dsOut))), strings.ToUpper(stripBlanks(ours))) {
				t.Errorf("DS mismatch:\nBIND: %s\nours: %s", dsOut, ours)
			}
		})
	}
}

func stripBlanks(s string) string {
	return strings.Join(strings.Fields(s), "")
}
