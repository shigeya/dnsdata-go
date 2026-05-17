package wire_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// buildResponseAH constructs a minimal DNS response message: one
// question + one answer of the given type and rdata. Useful for tests
// where we want to exercise [ParseMessage] without writing the
// fixture out by hand each time.
func buildResponseAH(t *testing.T, qname string, qtype uint16, ansName string, ansType uint16, ttl uint32, rdata []byte) []byte {
	t.Helper()
	var b wire.Builder
	b.AppendUint16(0x4242)             // ID
	b.AppendUint16(0x8180)             // flags: QR=1, RD=1, RA=1
	b.AppendUint16(1)                  // QDCOUNT
	b.AppendUint16(1)                  // ANCOUNT
	b.AppendUint16(0)                  // NSCOUNT
	b.AppendUint16(0)                  // ARCOUNT
	q, err := wire.DomainNameToWire(qname)
	if err != nil {
		t.Fatalf("DomainNameToWire(qname): %v", err)
	}
	b.AppendBytes(q)
	b.AppendUint16(qtype)
	b.AppendUint16(types.ClassIN)
	a, err := wire.DomainNameToWire(ansName)
	if err != nil {
		t.Fatalf("DomainNameToWire(ans): %v", err)
	}
	b.AppendBytes(a)
	b.AppendUint16(ansType)
	b.AppendUint16(types.ClassIN)
	b.AppendUint32(ttl)
	b.AppendUint16(uint16(len(rdata)))
	b.AppendBytes(rdata)
	return b.Clone()
}

func TestParseMessage_HeaderTruncated(t *testing.T) {
	_, err := wire.ParseMessage([]byte{0x00, 0x01})
	if !errors.Is(err, wire.ErrMessageMalformed) {
		t.Errorf("err = %v, want ErrMessageMalformed", err)
	}
}

func TestParseMessage_OneAnswerA(t *testing.T) {
	rdata := []byte{192, 0, 2, 1}
	msg := buildResponseAH(t, "example.com.", types.TypeA, "example.com.", types.TypeA, 300, rdata)
	m, err := wire.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if !m.Header.QR() {
		t.Errorf("expected QR flag set")
	}
	if m.Header.RCode() != 0 {
		t.Errorf("RCode = %d, want 0", m.Header.RCode())
	}
	if m.Question.Name != "example.com." {
		t.Errorf("qname = %q", m.Question.Name)
	}
	if m.Question.Type != types.TypeA {
		t.Errorf("qtype = %d", m.Question.Type)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(m.Answer))
	}
	rr := m.Answer[0]
	if rr.Name != "example.com." {
		t.Errorf("answer name = %q", rr.Name)
	}
	if rr.Type != types.TypeA || rr.Class != types.ClassIN {
		t.Errorf("type/class = %d/%d", rr.Type, rr.Class)
	}
	if rr.TTL != 300 {
		t.Errorf("TTL = %d", rr.TTL)
	}
	if string(rr.RData) != string(rdata) {
		t.Errorf("rdata mismatch")
	}
}

func TestRDataToString_A(t *testing.T) {
	got, err := wire.RDataToString(nil, types.TypeA, []byte{192, 0, 2, 1}, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "192.0.2.1" {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_AAAA(t *testing.T) {
	rdata := make([]byte, 16)
	rdata[0] = 0x20
	rdata[1] = 0x01
	rdata[15] = 0x01
	got, err := wire.RDataToString(nil, types.TypeAAAA, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "2001::1" {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_CNAME(t *testing.T) {
	target, err := wire.DomainNameToWire("alias.example.com.")
	if err != nil {
		t.Fatalf("DomainNameToWire: %v", err)
	}
	msg := buildResponseAH(t, "x.", types.TypeCNAME, "x.", types.TypeCNAME, 60, target)
	m, _ := wire.ParseMessage(msg)
	rr := m.Answer[0]
	got, err := wire.RDataToString(msg, rr.Type, rr.RData, rr.RDataStart)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "alias.example.com." {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_DNSKEY(t *testing.T) {
	// Flags=257, proto=3, algo=13, keydata=4 bytes.
	rdata := []byte{0x01, 0x01, 3, 13, 0xDE, 0xAD, 0xBE, 0xEF}
	got, err := wire.RDataToString(nil, types.TypeDNSKEY, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	// 0xDEADBEEF base64 = 3q2+7w==
	if got != "257 3 13 3q2+7w==" {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_DS(t *testing.T) {
	// KeyTag=12345 (0x3039), algo=13, digestType=2, digest=4 bytes
	rdata := []byte{0x30, 0x39, 13, 2, 0xAA, 0xBB, 0xCC, 0xDD}
	got, err := wire.RDataToString(nil, types.TypeDS, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "12345 13 2 aabbccdd" {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_RRSIG(t *testing.T) {
	// Build RRSIG: type=A, algo=13, labels=2, ttl=300, expire=20300101000000,
	// inception=20200101000000, keytag=12345, signer="example.com.", sig=4 bytes.
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, types.TypeA)
	rdata = append(rdata, 13) // algorithm
	rdata = append(rdata, 2)  // labels
	rdata = binary.BigEndian.AppendUint32(rdata, 300)
	rdata = binary.BigEndian.AppendUint32(rdata, 4070908800) // approx 2099
	rdata = binary.BigEndian.AppendUint32(rdata, 1577836800) // 2020-01-01
	rdata = binary.BigEndian.AppendUint16(rdata, 12345)
	signer, err := wire.DomainNameToWire("example.com.")
	if err != nil {
		t.Fatalf("DomainNameToWire: %v", err)
	}
	rdata = append(rdata, signer...)
	rdata = append(rdata, 0xFE, 0xED, 0xFA, 0xCE) // signature

	// Wrap in a message so the offsets line up.
	msg := buildResponseAH(t, "x.", types.TypeRRSIG, "x.", types.TypeRRSIG, 300, rdata)
	m, err := wire.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	rr := m.Answer[0]
	got, err := wire.RDataToString(msg, rr.Type, rr.RData, rr.RDataStart)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	// 0xFEEDFACE base64 = /u36zg==
	want := "A 13 2 300 4070908800 1577836800 12345 example.com. /u36zg=="
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRDataToString_NSEC(t *testing.T) {
	// next = "b.example.com.", types A + RRSIG (bit 1 and bit 46 in window 0).
	next, _ := wire.DomainNameToWire("b.example.com.")
	bitmap := []byte{
		0x00, // window 0
		0x06, // length 6 bytes
		0x40, // bit 1 (A)
		0x00, 0x00, 0x00, 0x00,
		0x02, // bit 46 (RRSIG)
	}
	rdata := append(next, bitmap...)
	msg := buildResponseAH(t, "x.", types.TypeNSEC, "x.", types.TypeNSEC, 60, rdata)
	m, _ := wire.ParseMessage(msg)
	rr := m.Answer[0]
	got, err := wire.RDataToString(msg, rr.Type, rr.RData, rr.RDataStart)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	want := "b.example.com. A RRSIG"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRDataToString_UnknownType_RFC3597(t *testing.T) {
	got, err := wire.RDataToString(nil, 65535, []byte{0xAB, 0xCD}, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "\\# 2 abcd" {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_A_WrongLength(t *testing.T) {
	_, err := wire.RDataToString(nil, types.TypeA, []byte{1, 2}, 0)
	if !errors.Is(err, wire.ErrRData) {
		t.Errorf("err = %v, want ErrRData", err)
	}
}

func TestParseMessage_RoundTripWithCompression(t *testing.T) {
	// Construct: question "example.com.", answer NS "ns.example.com."
	// using a compression pointer back to the question's "example.com."
	// offset 12.
	var b wire.Builder
	b.AppendUint16(1)      // ID
	b.AppendUint16(0x8180) // flags
	b.AppendUint16(1)      // QDCOUNT
	b.AppendUint16(1)      // ANCOUNT
	b.AppendUint16(0)
	b.AppendUint16(0)
	qname, _ := wire.DomainNameToWire("example.com.")
	b.AppendBytes(qname) // question name at offset 12
	b.AppendUint16(types.TypeNS)
	b.AppendUint16(types.ClassIN)
	// Answer name = pointer to offset 12.
	b.AppendUint8(0xC0)
	b.AppendUint8(0x0C)
	b.AppendUint16(types.TypeNS)
	b.AppendUint16(types.ClassIN)
	b.AppendUint32(60)
	// rdata = "ns" + pointer to offset 12 (= "example.com.")
	b.AppendUint16(uint16(1 + 2 + 2)) // rdlen = 1+2 ("ns") + 2 (pointer)
	b.AppendUint8(2)
	b.AppendUint8('n')
	b.AppendUint8('s')
	b.AppendUint8(0xC0)
	b.AppendUint8(0x0C)
	msg := b.Clone()
	m, err := wire.ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.Answer[0].Name != "example.com." {
		t.Errorf("answer name = %q", m.Answer[0].Name)
	}
	got, err := wire.RDataToString(msg, types.TypeNS, m.Answer[0].RData, m.Answer[0].RDataStart)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "ns.example.com." {
		t.Errorf("got %q", got)
	}
}
