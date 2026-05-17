package dnssec_test

import (
	"crypto/sha1"
	"reflect"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

func TestParseNSEC_PresentationFormat(t *testing.T) {
	n, err := dnssec.ParseNSEC(nil, "host.example.com. A MX RRSIG NSEC")
	if err != nil {
		t.Fatalf("ParseNSEC: %v", err)
	}
	if n.NextDomain != "host.example.com." {
		t.Errorf("NextDomain = %q", n.NextDomain)
	}
	for _, want := range []uint16{types.TypeA, types.TypeMX, types.TypeRRSIG, types.TypeNSEC} {
		if !n.CoversType(want) {
			t.Errorf("CoversType(%d) = false, want true", want)
		}
	}
	if n.CoversType(types.TypeAAAA) {
		t.Errorf("CoversType(AAAA) = true, want false")
	}
}

func TestEncodeDecodeTypeBitmap(t *testing.T) {
	want := []uint16{types.TypeA, types.TypeMX, types.TypeRRSIG, types.TypeNSEC}
	bitmap := dnssec.EncodeTypeBitmap(want)
	got, err := dnssec.DecodeTypeBitmap(bitmap)
	if err != nil {
		t.Fatalf("DecodeTypeBitmap: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip: got %v, want %v", got, want)
	}
}

func TestEncodeTypeBitmap_MultipleWindows(t *testing.T) {
	// URI=256 and CAA=257 live in window 1; A=1 lives in window 0.
	want := []uint16{types.TypeA, types.TypeURI, types.TypeCAA}
	bitmap := dnssec.EncodeTypeBitmap(want)
	got, err := dnssec.DecodeTypeBitmap(bitmap)
	if err != nil {
		t.Fatalf("DecodeTypeBitmap: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDecodeTypeBitmap_TruncatedWindow(t *testing.T) {
	// Window header says length 5 but only 2 bytes follow.
	if _, err := dnssec.DecodeTypeBitmap([]byte{0x00, 0x05, 0x40, 0x01}); err == nil {
		t.Error("DecodeTypeBitmap: expected error for truncated window")
	}
}

func TestNSEC_WireBody(t *testing.T) {
	n, err := dnssec.ParseNSEC(nil, "b.example.com. A NS SOA")
	if err != nil {
		t.Fatalf("ParseNSEC: %v", err)
	}
	var b wire.Builder
	if err := n.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if len(out) < 2 {
		t.Fatalf("WireBody too short: %d", len(out))
	}
	rdlen := int(out[0])<<8 | int(out[1])
	if rdlen != len(out)-2 {
		t.Errorf("rdlen = %d, want %d", rdlen, len(out)-2)
	}
}

func TestParseNSEC3_PresentationFormat(t *testing.T) {
	n, err := dnssec.ParseNSEC3(nil, "1 0 10 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	if n.HashAlgorithm != 1 {
		t.Errorf("HashAlgorithm = %d, want 1", n.HashAlgorithm)
	}
	if n.Flags != 0 {
		t.Errorf("Flags = %d, want 0", n.Flags)
	}
	if n.Iterations != 10 {
		t.Errorf("Iterations = %d, want 10", n.Iterations)
	}
	if len(n.Salt) != 2 || n.Salt[0] != 0xAA || n.Salt[1] != 0xBB {
		t.Errorf("Salt = % x, want aa bb", n.Salt)
	}
	if !n.CoversType(types.TypeA) {
		t.Errorf("CoversType(A) = false")
	}
	if !n.CoversType(types.TypeRRSIG) {
		t.Errorf("CoversType(RRSIG) = false")
	}
}

func TestParseNSEC3_EmptySalt(t *testing.T) {
	n, err := dnssec.ParseNSEC3(nil, "1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	if len(n.Salt) != 0 {
		t.Errorf("Salt length = %d, want 0", len(n.Salt))
	}
	if n.Iterations != 0 {
		t.Errorf("Iterations = %d, want 0", n.Iterations)
	}
}

func TestComputeNSEC3Hash_LengthIsSHA1(t *testing.T) {
	h, err := dnssec.ComputeNSEC3Hash("example.", 1, 0, nil)
	if err != nil {
		t.Fatalf("ComputeNSEC3Hash: %v", err)
	}
	if len(h) != sha1.Size {
		t.Errorf("hash length = %d, want %d", len(h), sha1.Size)
	}
}

func TestNSEC3_WireBody(t *testing.T) {
	n, err := dnssec.ParseNSEC3(nil, "1 0 10 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A NS")
	if err != nil {
		t.Fatalf("ParseNSEC3: %v", err)
	}
	var b wire.Builder
	if err := n.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := int(out[0])<<8 | int(out[1])
	if rdlen != len(out)-2 {
		t.Errorf("rdlen = %d, want %d", rdlen, len(out)-2)
	}
}

func TestParseNSEC3Param_PresentationFormat(t *testing.T) {
	p, err := dnssec.ParseNSEC3Param(nil, "1 0 10 AABBCC")
	if err != nil {
		t.Fatalf("ParseNSEC3Param: %v", err)
	}
	if p.HashAlgorithm != 1 || p.Flags != 0 || p.Iterations != 10 {
		t.Errorf("unexpected fields: %+v", p)
	}
	if len(p.Salt) != 3 {
		t.Errorf("Salt length = %d, want 3", len(p.Salt))
	}
}

func TestNSEC3Param_WireBody(t *testing.T) {
	p, err := dnssec.ParseNSEC3Param(nil, "1 0 0 -")
	if err != nil {
		t.Fatalf("ParseNSEC3Param: %v", err)
	}
	var b wire.Builder
	if err := p.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlen(2) + hash(1) + flags(1) + iter(2) + saltlen(1) + salt(0)
	if len(out) != 2+5 {
		t.Errorf("WireBody length = %d, want 7", len(out))
	}
}
