package dnssec_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

const sampleDSValue = "12345 5 2 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func newDSRR(t *testing.T) *zone.ResourceRecord {
	t.Helper()
	rr, err := zone.NewResourceRecord("example.com.", 3600, "IN", "DS", sampleDSValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord(DS): %v", err)
	}
	return rr
}

func TestParseDS_PresentationFormat(t *testing.T) {
	rr := newDSRR(t)
	d, err := dnssec.ParseDS(rr, sampleDSValue)
	if err != nil {
		t.Fatalf("ParseDS: %v", err)
	}
	if d.KeyTag != 12345 {
		t.Errorf("KeyTag = %d, want 12345", d.KeyTag)
	}
	if d.Algorithm != 5 {
		t.Errorf("Algorithm = %d, want 5", d.Algorithm)
	}
	if d.DigestType != 2 {
		t.Errorf("DigestType = %d, want 2", d.DigestType)
	}
	if len(d.Digest) != sha256.Size {
		t.Errorf("Digest length = %d, want %d (SHA-256)", len(d.Digest), sha256.Size)
	}
}

func TestParseDS_Malformed(t *testing.T) {
	_, err := dnssec.ParseDS(nil, "not a ds value")
	if !errors.Is(err, dnssec.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestParseDS_AcceptsWhitespaceInDigest(t *testing.T) {
	// Real zone files commonly soft-wrap long DS digests with spaces.
	v := "12345 5 2 abcdef01 23456789 abcdef01 23456789 abcdef01 23456789 abcdef01 23456789"
	d, err := dnssec.ParseDS(nil, v)
	if err != nil {
		t.Fatalf("ParseDS: %v", err)
	}
	if len(d.Digest) != sha256.Size {
		t.Errorf("Digest length = %d, want %d", len(d.Digest), sha256.Size)
	}
}

func TestDS_WireBody(t *testing.T) {
	rr := newDSRR(t)
	d, err := dnssec.ParseDS(rr, sampleDSValue)
	if err != nil {
		t.Fatalf("ParseDS: %v", err)
	}
	var b wire.Builder
	if err := d.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// rdlen(2) + keytag(2) + algo(1) + digesttype(1) + digest(32)
	if want := 2 + 4 + sha256.Size; len(out) != want {
		t.Errorf("WireBody length = %d, want %d", len(out), want)
	}
	rdlen := int(out[0])<<8 | int(out[1])
	if rdlen != 4+sha256.Size {
		t.Errorf("rdlen = %d, want %d", rdlen, 4+sha256.Size)
	}
}

// Round-trip: build a DS record whose digest matches the SHA-256 of a
// known DNSKey's DSDigestData, then assert VerifyDigest accepts it and
// rejects a tampered digest.
func TestDS_VerifyDigest_RoundTrip(t *testing.T) {
	keyRR, err := zone.NewResourceRecord("example.com.", 3600, "IN", "DNSKEY", sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord(DNSKEY): %v", err)
	}
	k, err := dnssec.ParseDNSKey(keyRR, sampleDNSKEYValue)
	if err != nil {
		t.Fatalf("ParseDNSKey: %v", err)
	}
	digestInput, err := k.DSDigestData()
	if err != nil {
		t.Fatalf("DSDigestData: %v", err)
	}
	sum := sha256.Sum256(digestInput)
	hexDigest := hex.EncodeToString(sum[:])

	good := strings.Join([]string{
		toString(k.KeyTag), toString(k.Algorithm), "2", hexDigest,
	}, " ")
	d, err := dnssec.ParseDS(nil, good)
	if err != nil {
		t.Fatalf("ParseDS(good): %v", err)
	}
	ok, err := d.VerifyDigest(digestInput)
	if err != nil {
		t.Fatalf("VerifyDigest(good): %v", err)
	}
	if !ok {
		t.Errorf("VerifyDigest returned false for matching DS")
	}

	bad := strings.Join([]string{
		toString(k.KeyTag), toString(k.Algorithm), "2", strings.Repeat("00", sha256.Size),
	}, " ")
	d2, err := dnssec.ParseDS(nil, bad)
	if err != nil {
		t.Fatalf("ParseDS(bad): %v", err)
	}
	bad2, err := d2.VerifyDigest(digestInput)
	if err != nil {
		t.Fatalf("VerifyDigest(bad): %v", err)
	}
	if bad2 {
		t.Errorf("VerifyDigest returned true for mismatched DS")
	}
}

func TestDS_VerifyDigest_UnsupportedDigestType(t *testing.T) {
	// Digest type 99 is unassigned; VerifyDigest should refuse early.
	d := dnssec.NewDS(nil, 12345, 5, 99, make([]byte, 16))
	_, err := d.VerifyDigest([]byte{1, 2, 3})
	if !errors.Is(err, dnssec.ErrUnsupportedAlgorithm) {
		t.Errorf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// toString is a tiny stringer used by the test data assembler so we
// avoid pulling fmt into the imports list for a single conversion.
func toString[T uint8 | uint16 | uint32](v T) string {
	var buf [20]byte
	pos := len(buf)
	n := uint64(v)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
