package wire_test

import (
	"encoding/binary"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// rrInMessage returns the rdata + RDataStart of an rrtype answer
// wrapped in a synthetic response message, so RDataToString can be
// called against decoders that follow compression pointers within
// rdata.
func rrInMessage(t *testing.T, qtype uint16, rdata []byte) (msg []byte, rdataStart int) {
	t.Helper()
	msgBytes := buildResponseAH(t, "x.", qtype, "x.", qtype, 60, rdata)
	m, err := wire.ParseMessage(msgBytes)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	return msgBytes, m.Answer[0].RDataStart
}

func TestRDataToString_MX(t *testing.T) {
	exch, _ := wire.DomainNameToWire("mail.example.com.")
	rdata := make([]byte, 0, 2+len(exch))
	rdata = binary.BigEndian.AppendUint16(rdata, 10)
	rdata = append(rdata, exch...)
	msg, start := rrInMessage(t, types.TypeMX, rdata)
	got, err := wire.RDataToString(msg, types.TypeMX, rdata, start)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "10 mail.example.com." {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_TXT(t *testing.T) {
	// Two character-strings: `hello` and `wo"rld`. The second exercises
	// the txtQuote escape path.
	rdata := []byte{}
	rdata = append(rdata, 5, 'h', 'e', 'l', 'l', 'o')
	rdata = append(rdata, 6, 'w', 'o', '"', 'r', 'l', 'd')
	got, err := wire.RDataToString(nil, types.TypeTXT, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != `"hello" "wo\"rld"` {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_SOA(t *testing.T) {
	mname, _ := wire.DomainNameToWire("ns1.example.com.")
	rname, _ := wire.DomainNameToWire("hostmaster.example.com.")
	rdata := append([]byte{}, mname...)
	rdata = append(rdata, rname...)
	rdata = binary.BigEndian.AppendUint32(rdata, 2024010101)
	rdata = binary.BigEndian.AppendUint32(rdata, 3600)
	rdata = binary.BigEndian.AppendUint32(rdata, 600)
	rdata = binary.BigEndian.AppendUint32(rdata, 86400)
	rdata = binary.BigEndian.AppendUint32(rdata, 300)
	msg, start := rrInMessage(t, types.TypeSOA, rdata)
	got, err := wire.RDataToString(msg, types.TypeSOA, rdata, start)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	want := "ns1.example.com. hostmaster.example.com. 2024010101 3600 600 86400 300"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRDataToString_SRV(t *testing.T) {
	target, _ := wire.DomainNameToWire("server.example.com.")
	rdata := []byte{}
	rdata = binary.BigEndian.AppendUint16(rdata, 10) // priority
	rdata = binary.BigEndian.AppendUint16(rdata, 60) // weight
	rdata = binary.BigEndian.AppendUint16(rdata, 80) // port
	rdata = append(rdata, target...)
	msg, start := rrInMessage(t, types.TypeSRV, rdata)
	got, err := wire.RDataToString(msg, types.TypeSRV, rdata, start)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "10 60 80 server.example.com." {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_CAA(t *testing.T) {
	tag := "issue"
	value := "letsencrypt.org"
	rdata := []byte{0}                       // flags
	rdata = append(rdata, byte(len(tag)))    // tag length
	rdata = append(rdata, []byte(tag)...)    // tag
	rdata = append(rdata, []byte(value)...)  // value (rest of rdata)
	got, err := wire.RDataToString(nil, types.TypeCAA, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != `0 issue "letsencrypt.org"` {
		t.Errorf("got %q", got)
	}
}

func TestRDataToString_NSEC3(t *testing.T) {
	rdata := []byte{}
	rdata = append(rdata, 1)   // hash algo (SHA-1)
	rdata = append(rdata, 0)   // flags
	rdata = binary.BigEndian.AppendUint16(rdata, 10) // iterations
	rdata = append(rdata, 2)   // salt length
	rdata = append(rdata, 0xAA, 0xBB)
	rdata = append(rdata, 20)  // next-hash length (SHA-1 = 20 bytes)
	for i := 0; i < 20; i++ {
		rdata = append(rdata, byte(i))
	}
	// Type bitmap with just RRSIG (type 46, window 0).
	rdata = append(rdata, 0, 6, 0, 0, 0, 0, 0, 0x02)
	got, err := wire.RDataToString(nil, types.TypeNSEC3, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got == "" || !contains(got, "1 0 10 AABB") || !contains(got, "RRSIG") {
		t.Errorf("got %q (missing expected fragments)", got)
	}
}

func TestRDataToString_NSEC3_EmptySalt(t *testing.T) {
	rdata := []byte{}
	rdata = append(rdata, 1, 0)
	rdata = binary.BigEndian.AppendUint16(rdata, 0)
	rdata = append(rdata, 0)  // empty salt
	rdata = append(rdata, 20) // next-hash length
	for i := 0; i < 20; i++ {
		rdata = append(rdata, 0)
	}
	got, err := wire.RDataToString(nil, types.TypeNSEC3, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	// Empty salt is rendered as "-"
	if !contains(got, " - ") {
		t.Errorf("expected ' - ' (empty salt placeholder) in %q", got)
	}
}

func TestRDataToString_NSEC3PARAM(t *testing.T) {
	rdata := []byte{1, 0}
	rdata = binary.BigEndian.AppendUint16(rdata, 5)
	rdata = append(rdata, 1, 0xCC) // 1-byte salt
	got, err := wire.RDataToString(nil, types.TypeNSEC3PARAM, rdata, 0)
	if err != nil {
		t.Fatalf("RDataToString: %v", err)
	}
	if got != "1 0 5 CC" {
		t.Errorf("got %q", got)
	}
}

func TestHeaderFlags_Accessors(t *testing.T) {
	// 0x85B0 = QR | AA | RD | RA | AD | CD (TC and OPCODE / RCODE bits
	// cleared). Bit positions per RFC 1035 §4.1.1 + RFC 4035 §3.
	h := wire.Header{Flags: 0x85B0}
	if !h.QR() || !h.AA() || !h.RD() || !h.RA() || !h.AD() || !h.CD() {
		t.Errorf("flag accessor mismatch on 0x%04x: QR=%v AA=%v RD=%v RA=%v AD=%v CD=%v",
			h.Flags, h.QR(), h.AA(), h.RD(), h.RA(), h.AD(), h.CD())
	}
	if h.TC() {
		t.Errorf("TC unexpectedly true")
	}
	// Set TC.
	h.Flags |= 0x0200
	if !h.TC() {
		t.Errorf("TC stayed false after setting bit")
	}
}

// contains is a tiny utility avoiding strings.Contains import here.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
