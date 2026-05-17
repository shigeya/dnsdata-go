package doh

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

func TestBuildQuery_HeaderLayout(t *testing.T) {
	msg, err := buildQueryWithID(0x4242, "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("buildQueryWithID: %v", err)
	}
	if len(msg) < 12 {
		t.Fatalf("message too short: %d bytes", len(msg))
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd := binary.BigEndian.Uint16(msg[4:6])
	an := binary.BigEndian.Uint16(msg[6:8])
	ns := binary.BigEndian.Uint16(msg[8:10])
	ar := binary.BigEndian.Uint16(msg[10:12])

	if id != 0x4242 {
		t.Errorf("ID = 0x%04x, want 0x4242", id)
	}
	if flags&0x0100 == 0 {
		t.Errorf("RD bit not set in flags 0x%04x", flags)
	}
	if qd != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qd)
	}
	if an != 0 || ns != 0 {
		t.Errorf("AN/NS counts non-zero: an=%d ns=%d", an, ns)
	}
	if ar != 1 {
		t.Errorf("ARCOUNT = %d, want 1 (OPT)", ar)
	}
}

func TestBuildQuery_QuestionAndOPT(t *testing.T) {
	msg, err := buildQueryWithID(0x1234, "example.com.", types.TypeDNSKEY)
	if err != nil {
		t.Fatalf("buildQueryWithID: %v", err)
	}
	// Header is 12 bytes; question follows.
	// example.com. encodes as \x07example\x03com\x00 (13 bytes).
	qstart := 12
	wantName := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	for i, b := range wantName {
		if msg[qstart+i] != b {
			t.Errorf("qname byte %d = 0x%02x, want 0x%02x", i, msg[qstart+i], b)
		}
	}
	off := qstart + len(wantName)
	qtype := binary.BigEndian.Uint16(msg[off : off+2])
	qclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
	if qtype != types.TypeDNSKEY {
		t.Errorf("QTYPE = %d, want %d", qtype, types.TypeDNSKEY)
	}
	if qclass != types.ClassIN {
		t.Errorf("QCLASS = %d, want %d", qclass, types.ClassIN)
	}

	// OPT pseudo-RR: root name (0x00) + type 41 + class 4096 + TTL 0x8000_0000 + RDLEN 0
	optStart := off + 4
	if msg[optStart] != 0x00 {
		t.Errorf("OPT name byte = 0x%02x, want 0x00 (root)", msg[optStart])
	}
	optType := binary.BigEndian.Uint16(msg[optStart+1 : optStart+3])
	optClass := binary.BigEndian.Uint16(msg[optStart+3 : optStart+5])
	optTTL := binary.BigEndian.Uint32(msg[optStart+5 : optStart+9])
	optRDLen := binary.BigEndian.Uint16(msg[optStart+9 : optStart+11])
	if optType != 41 {
		t.Errorf("OPT type = %d, want 41", optType)
	}
	if optClass != 4096 {
		t.Errorf("OPT class (UDP payload size) = %d, want 4096", optClass)
	}
	if optTTL&0x8000 == 0 {
		t.Errorf("OPT TTL high-bit (DO) not set: 0x%08x", optTTL)
	}
	if optRDLen != 0 {
		t.Errorf("OPT RDLEN = %d, want 0", optRDLen)
	}
}

func TestBuildQuery_AcceptsNonFQDN(t *testing.T) {
	// Trailing dot should be auto-appended.
	msg1, err := buildQueryWithID(1, "example.com", types.TypeA)
	if err != nil {
		t.Fatalf("buildQueryWithID(no dot): %v", err)
	}
	msg2, err := buildQueryWithID(1, "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("buildQueryWithID(dot): %v", err)
	}
	if len(msg1) != len(msg2) {
		t.Errorf("lengths differ: %d vs %d", len(msg1), len(msg2))
	}
}

func TestBuildQuery_RejectsInvalidLabel(t *testing.T) {
	tooLong := strings.Repeat("a", 70)
	_, err := BuildQuery(tooLong+".example.com.", types.TypeA)
	if !errors.Is(err, ErrInvalidQName) {
		t.Errorf("err = %v, want ErrInvalidQName", err)
	}
}

func TestBuildQuery_RandomIDsDiffer(t *testing.T) {
	// Probabilistic: two consecutive BuildQuery calls should almost
	// certainly draw different IDs. Failure rate is 1/65536.
	a, err := BuildQuery("example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("BuildQuery(a): %v", err)
	}
	b, err := BuildQuery("example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("BuildQuery(b): %v", err)
	}
	idA := binary.BigEndian.Uint16(a[0:2])
	idB := binary.BigEndian.Uint16(b[0:2])
	if idA == idB {
		t.Logf("ID collision (1/65536): %#x", idA) // not a hard failure
	}
}
