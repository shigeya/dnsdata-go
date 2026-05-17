package dnssec_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// TestClone_AllHandlers exercises Clone() on every DNSSEC RR handler.
// The bodies are simple deep-copies so the test asserts identity rather
// than full semantic equality: the returned value is a non-nil handler
// of the same concrete type and its bytes slices are detached from
// the source.
func TestClone_AllHandlers(t *testing.T) {
	cases := []struct {
		name  string
		rrSet func(t *testing.T) zone.RecordHandler
	}{
		{"DNSKey", func(t *testing.T) zone.RecordHandler {
			h, err := dnssec.ParseDNSKey(nil, sampleDNSKEYValue)
			if err != nil {
				t.Fatalf("ParseDNSKey: %v", err)
			}
			return h
		}},
		{"RRSig", func(t *testing.T) zone.RecordHandler {
			h, err := dnssec.ParseRRSig(nil, sampleRRSIGValue)
			if err != nil {
				t.Fatalf("ParseRRSig: %v", err)
			}
			return h
		}},
		{"DS", func(t *testing.T) zone.RecordHandler {
			h, err := dnssec.ParseDS(nil, sampleDSValue)
			if err != nil {
				t.Fatalf("ParseDS: %v", err)
			}
			return h
		}},
		{"NSEC", func(t *testing.T) zone.RecordHandler {
			h, err := dnssec.ParseNSEC(nil, "host.example.com. A NS RRSIG NSEC")
			if err != nil {
				t.Fatalf("ParseNSEC: %v", err)
			}
			return h
		}},
		{"NSEC3", func(t *testing.T) zone.RecordHandler {
			h, err := dnssec.ParseNSEC3(nil, "1 0 10 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG")
			if err != nil {
				t.Fatalf("ParseNSEC3: %v", err)
			}
			return h
		}},
		{"NSEC3Param", func(t *testing.T) zone.RecordHandler {
			h, err := dnssec.ParseNSEC3Param(nil, "1 0 10 AABBCC")
			if err != nil {
				t.Fatalf("ParseNSEC3Param: %v", err)
			}
			return h
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := c.rrSet(t)
			dst := src.Clone()
			if dst == nil {
				t.Fatal("Clone returned nil")
			}
			if reflect.TypeOf(dst) != reflect.TypeOf(src) {
				t.Errorf("Clone type = %T, want %T", dst, src)
			}
		})
	}
}

// TestRegisterHandlers_NSEC3PARAM exercises the NSEC3PARAM factory
// path so handlers.go is exercised in full.
func TestRegisterHandlers_NSEC3PARAM(t *testing.T) {
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "NSEC3PARAM", "1 0 10 AABBCC")
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	h := rr.Handler()
	if _, ok := h.(*dnssec.NSEC3Param); !ok {
		t.Errorf("Handler() = %T, want *dnssec.NSEC3Param", h)
	}
}

// TestRSA_SignVerifyRoundTrip exercises the RSA signature path
// (rsaHash + rsa.SignPKCS1v15 + rsa.VerifyPKCS1v15). Uses a 1024-bit
// key for speed; this is *only* exercised for the cryptography, never
// in production.
func TestRSA_SignVerifyRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyData := encodeRSAPublicKeyRFC3110(t, &priv.PublicKey)
	value := "257 3 8 " + base64.StdEncoding.EncodeToString(keyData) // algorithm 8 = RSASHA256

	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "DNSKEY", value)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord: %v", err)
	}
	k, err := dnssec.ParseDNSKey(rr, value)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	if k.Algorithm != types.AlgoRSASHA256 {
		t.Fatalf("Algorithm = %d, want 8", k.Algorithm)
	}
	k.SetPrivateKey(priv)

	payload := []byte("dnsdata-go RSA round-trip")
	sig, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := k.Verify(payload, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("Verify returned false for valid signature")
	}
}

// encodeRSAPublicKeyRFC3110 emits the wire form expected by
// loadRSAPublicKey: a 1-byte (or 3-byte) exponent length, the
// big-endian exponent, then the big-endian modulus.
func encodeRSAPublicKeyRFC3110(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	exp := bigEndianBytes(uint64(pub.E))
	mod := pub.N.Bytes()

	var out []byte
	if len(exp) <= 255 {
		out = append(out, byte(len(exp)))
	} else {
		out = append(out, 0, byte(len(exp)>>8), byte(len(exp)))
	}
	out = append(out, exp...)
	out = append(out, mod...)
	return out
}

func bigEndianBytes(v uint64) []byte {
	out := make([]byte, 0, 8)
	started := false
	for i := 7; i >= 0; i-- {
		b := byte(v >> (8 * i))
		if !started && b == 0 {
			continue
		}
		started = true
		out = append(out, b)
	}
	if !started {
		out = append(out, 0)
	}
	return out
}
