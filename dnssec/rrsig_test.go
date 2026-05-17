package dnssec_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

const sampleRRSIGValue = "A 5 3 86400 20121201000000 20121101000000 12345 example.com. dGVzdHNpZ25hdHVyZQ=="

func newRRSIGRR(t *testing.T) *zone.ResourceRecord {
	t.Helper()
	rr, err := zone.NewResourceRecord("www.example.com.", 86400, "IN", "RRSIG", sampleRRSIGValue)
	if err != nil {
		t.Fatalf("zone.NewResourceRecord(RRSIG): %v", err)
	}
	return rr
}

func TestParseRRSig_PresentationFormat(t *testing.T) {
	rr := newRRSIGRR(t)
	s, err := dnssec.ParseRRSig(rr, sampleRRSIGValue)
	if err != nil {
		t.Fatalf("ParseRRSig: %v", err)
	}
	if s.TypeCovered != types.TypeA {
		t.Errorf("TypeCovered = %d, want %d (A)", s.TypeCovered, types.TypeA)
	}
	if s.Algorithm != types.AlgoRSASHA1 {
		t.Errorf("Algorithm = %d, want 5", s.Algorithm)
	}
	if s.Labels != 3 {
		t.Errorf("Labels = %d, want 3", s.Labels)
	}
	if s.OriginalTTL != 86400 {
		t.Errorf("OriginalTTL = %d, want 86400", s.OriginalTTL)
	}
	if s.KeyTag != 12345 {
		t.Errorf("KeyTag = %d, want 12345", s.KeyTag)
	}
	if s.Signer != "example.com." {
		t.Errorf("Signer = %q, want %q", s.Signer, "example.com.")
	}
	if len(s.Signature) == 0 {
		t.Errorf("Signature is empty")
	}
}

func TestParseRRSig_Malformed(t *testing.T) {
	_, err := dnssec.ParseRRSig(nil, "not an rrsig value")
	if !errors.Is(err, dnssec.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestParseRRSig_DatetimeFormats(t *testing.T) {
	rr := newRRSIGRR(t)
	s, err := dnssec.ParseRRSig(rr, sampleRRSIGValue)
	if err != nil {
		t.Fatalf("ParseRRSig: %v", err)
	}
	wantExpire := time.Date(2012, 12, 1, 0, 0, 0, 0, time.UTC).Unix()
	if s.Expire != wantExpire {
		t.Errorf("Expire = %d, want %d", s.Expire, wantExpire)
	}
	wantInception := time.Date(2012, 11, 1, 0, 0, 0, 0, time.UTC).Unix()
	if s.Inception != wantInception {
		t.Errorf("Inception = %d, want %d", s.Inception, wantInception)
	}

	// Plain-integer epoch form should also work.
	epochVal := strings.Replace(sampleRRSIGValue, "20121201000000", "1354320000", 1)
	epochVal = strings.Replace(epochVal, "20121101000000", "1351728000", 1)
	s2, err := dnssec.ParseRRSig(rr, epochVal)
	if err != nil {
		t.Fatalf("ParseRRSig(epoch): %v", err)
	}
	if s2.Expire != 1354320000 {
		t.Errorf("Expire (epoch form) = %d, want 1354320000", s2.Expire)
	}
}

func TestRRSig_RDataDigestTarget(t *testing.T) {
	rr := newRRSIGRR(t)
	s, err := dnssec.ParseRRSig(rr, sampleRRSIGValue)
	if err != nil {
		t.Fatalf("ParseRRSig: %v", err)
	}
	dt, err := s.RDataDigestTarget()
	if err != nil {
		t.Fatalf("RDataDigestTarget: %v", err)
	}
	// type_covered(2) + algo(1) + labels(1) + orig_ttl(4) + expire(4) + inception(4) + keytag(2) + signer_wire
	if dt[0] != 0x00 || dt[1] != 0x01 {
		t.Errorf("type_covered bytes = 0x%02x%02x, want 0x0001 (A)", dt[0], dt[1])
	}
	if dt[2] != 5 {
		t.Errorf("algorithm byte = %d, want 5", dt[2])
	}
	if dt[3] != 3 {
		t.Errorf("labels byte = %d, want 3", dt[3])
	}
}

func TestRRSig_WireBody(t *testing.T) {
	rr := newRRSIGRR(t)
	s, err := dnssec.ParseRRSig(rr, sampleRRSIGValue)
	if err != nil {
		t.Fatalf("ParseRRSig: %v", err)
	}
	var b wire.Builder
	if err := s.WireBody(&b); err != nil {
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

func TestRRSig_ValueString(t *testing.T) {
	rr := newRRSIGRR(t)
	s, err := dnssec.ParseRRSig(rr, sampleRRSIGValue)
	if err != nil {
		t.Fatalf("ParseRRSig: %v", err)
	}
	vs := s.ValueString()
	if !strings.Contains(vs, "A 5 3 86400") {
		t.Errorf("ValueString %q missing 'A 5 3 86400'", vs)
	}
	if !strings.Contains(vs, "example.com.") {
		t.Errorf("ValueString %q missing signer", vs)
	}
}
