package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/wire"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/opt_rr.spec.ts.

func TestEDNS_DefaultEncode(t *testing.T) {
	// Default OPT: udp_payload_size 4096, no DO, no options.
	var b wire.Builder
	(&wire.EDNS{}).Encode(&b)
	out := b.Bytes()
	if len(out) != 11 {
		t.Fatalf("encoded length = %d, want 11 (root + 2+2+4+2)", len(out))
	}
	if out[0] != 0 {
		t.Errorf("NAME = %d, want 0", out[0])
	}
	if got := binary.BigEndian.Uint16(out[1:3]); got != wire.OPTTypeCode {
		t.Errorf("TYPE = %d, want %d", got, wire.OPTTypeCode)
	}
	if got := binary.BigEndian.Uint16(out[3:5]); got != wire.DefaultUDPPayloadSize {
		t.Errorf("CLASS = %d, want %d", got, wire.DefaultUDPPayloadSize)
	}
	if got := binary.BigEndian.Uint32(out[5:9]); got != 0 {
		t.Errorf("TTL = %08x, want 0", got)
	}
	if got := binary.BigEndian.Uint16(out[9:11]); got != 0 {
		t.Errorf("RDLEN = %d, want 0", got)
	}
}

func TestEDNS_DOBit(t *testing.T) {
	var b wire.Builder
	(&wire.EDNS{DOBit: true}).Encode(&b)
	out := b.Bytes()
	// DO bit is the high bit of the third TTL octet (offset 7).
	if out[7]&0x80 == 0 {
		t.Errorf("DO bit not set: TTL byte 7 = 0x%02x", out[7])
	}
}

func TestEDNS_ExtendedRCODEAndVersion(t *testing.T) {
	var b wire.Builder
	(&wire.EDNS{ExtendedRCODE: 1, Version: 2, DOBit: true}).Encode(&b)
	out := b.Bytes()
	if out[5] != 1 {
		t.Errorf("extended_rcode = %d, want 1", out[5])
	}
	if out[6] != 2 {
		t.Errorf("version = %d, want 2", out[6])
	}
	if out[7]&0x80 == 0 {
		t.Errorf("DO bit lost when extended_rcode/version set")
	}
}

func TestEDNS_EncodeOption(t *testing.T) {
	nsid := []byte{'n', 's', '1'}
	var b wire.Builder
	(&wire.EDNS{Options: []wire.EDNSOption{{Code: wire.EDNSOptionNSID, Data: nsid}}}).Encode(&b)
	out := b.Bytes()
	// fixed 11-byte OPT header + (code(2)+length(2)+data(3))
	if len(out) != 11+4+3 {
		t.Fatalf("encoded length = %d, want 18", len(out))
	}
	if got := binary.BigEndian.Uint16(out[9:11]); got != 7 {
		t.Errorf("RDLEN = %d, want 7", got)
	}
	if got := binary.BigEndian.Uint16(out[11:13]); got != wire.EDNSOptionNSID {
		t.Errorf("option code = %d, want %d", got, wire.EDNSOptionNSID)
	}
	if got := binary.BigEndian.Uint16(out[13:15]); got != 3 {
		t.Errorf("option length = %d, want 3", got)
	}
	if !bytes.Equal(out[15:18], nsid) {
		t.Errorf("option data = %x, want %x", out[15:18], nsid)
	}
}

func TestEDNS_EncodeMultipleOptions(t *testing.T) {
	opt := &wire.EDNS{
		Options: []wire.EDNSOption{
			{Code: wire.EDNSOptionNSID, Data: []byte{'n', 's', '1'}},
			{Code: wire.EDNSOptionCookie, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
	}
	var b wire.Builder
	opt.Encode(&b)
	out := b.Bytes()
	rdlen := binary.BigEndian.Uint16(out[9:11])
	// (4+3) + (4+8) = 19
	if rdlen != 19 {
		t.Errorf("RDLEN = %d, want 19", rdlen)
	}
}

func TestEDNS_DecodeRoundTrip(t *testing.T) {
	cookie := make([]byte, 24)
	for i := range cookie {
		cookie[i] = byte(i)
	}
	original := &wire.EDNS{
		UDPPayloadSize: 1232,
		DOBit:          true,
		Options: []wire.EDNSOption{
			{Code: wire.EDNSOptionNSID, Data: []byte{'n', 's', '1'}},
			{Code: wire.EDNSOptionCookie, Data: cookie},
		},
	}
	var b wire.Builder
	original.Encode(&b)
	out := b.Bytes()
	// DecodeOPT expects the buffer to start at the TYPE byte (NAME already consumed).
	parsed, err := wire.DecodeOPT(out[1:])
	if err != nil {
		t.Fatalf("DecodeOPT: %v", err)
	}
	if parsed.UDPPayloadSize != 1232 {
		t.Errorf("UDPPayloadSize = %d, want 1232", parsed.UDPPayloadSize)
	}
	if !parsed.DOBit {
		t.Errorf("DOBit = false, want true")
	}
	if len(parsed.Options) != 2 {
		t.Fatalf("options len = %d, want 2", len(parsed.Options))
	}
	if parsed.Options[0].Code != wire.EDNSOptionNSID || !bytes.Equal(parsed.Options[0].Data, []byte{'n', 's', '1'}) {
		t.Errorf("Options[0] = {code=%d data=%x}", parsed.Options[0].Code, parsed.Options[0].Data)
	}
	if parsed.Options[1].Code != wire.EDNSOptionCookie || !bytes.Equal(parsed.Options[1].Data, cookie) {
		t.Errorf("Options[1] = {code=%d data=%x}", parsed.Options[1].Code, parsed.Options[1].Data)
	}
}

func TestEDNS_DecodeExtendedRCODE(t *testing.T) {
	var b wire.Builder
	(&wire.EDNS{ExtendedRCODE: 5, Version: 1}).Encode(&b)
	parsed, err := wire.DecodeOPT(b.Bytes()[1:])
	if err != nil {
		t.Fatalf("DecodeOPT: %v", err)
	}
	if parsed.ExtendedRCODE != 5 || parsed.Version != 1 || parsed.DOBit {
		t.Errorf("parsed = {rcode=%d version=%d do=%v}",
			parsed.ExtendedRCODE, parsed.Version, parsed.DOBit)
	}
}

func TestEDNS_DecodeRejectsShortInput(t *testing.T) {
	if _, err := wire.DecodeOPT(make([]byte, 5)); !errors.Is(err, wire.ErrOPT) {
		t.Errorf("err = %v, want ErrOPT", err)
	}
}

func TestEDNS_DecodeRejectsWrongType(t *testing.T) {
	// type field = 1 (A), not 41 (OPT).
	data := make([]byte, 10)
	binary.BigEndian.PutUint16(data[0:2], 1)
	if _, err := wire.DecodeOPT(data); !errors.Is(err, wire.ErrOPT) {
		t.Errorf("err = %v, want ErrOPT", err)
	}
}

func TestEDNS_DecodeRejectsOversizedOption(t *testing.T) {
	// Construct a minimal OPT where the single option claims more data
	// than RDLENGTH carries.
	buf := []byte{
		0, 41, // TYPE = OPT
		0x10, 0x00, // CLASS = 4096
		0, 0, 0, 0, // TTL
		0, 5, // RDLEN = 5
		0, 3, // option code (NSID)
		0, 4, // option length = 4
		0xff, // only one option-data byte present (length claims 4)
	}
	if _, err := wire.DecodeOPT(buf); !errors.Is(err, wire.ErrOPT) {
		t.Errorf("err = %v, want ErrOPT", err)
	}
}

func TestEDNS_FindOption(t *testing.T) {
	opt := &wire.EDNS{
		Options: []wire.EDNSOption{
			{Code: wire.EDNSOptionNSID, Data: []byte{'n', 's', '1'}},
			{Code: wire.EDNSOptionCookie, Data: []byte{1, 2, 3, 4}},
		},
	}
	got, ok := opt.FindOption(wire.EDNSOptionNSID)
	if !ok {
		t.Fatalf("FindOption(NSID) = ok=false")
	}
	if got.Code != wire.EDNSOptionNSID {
		t.Errorf("FindOption returned code %d", got.Code)
	}
	if _, ok := (&wire.EDNS{}).FindOption(wire.EDNSOptionNSID); ok {
		t.Errorf("FindOption on empty EDNS returned ok=true")
	}
	if _, ok := (*wire.EDNS)(nil).FindOption(wire.EDNSOptionNSID); ok {
		t.Errorf("FindOption on nil receiver returned ok=true")
	}
}

func TestEDNS_BuildQueryParity(t *testing.T) {
	// BuildQuery emits a hand-rolled OPT at the end of the message. Make
	// sure the new wire.EDNS encoder produces the same trailing bytes.
	q, err := wire.BuildQueryWithID(0x1234, "example.com.", 1)
	if err != nil {
		t.Fatalf("BuildQueryWithID: %v", err)
	}
	// example.com. → 8+example + 4+com + 1 root = 13 bytes
	headerEnd := 12 + 13 + 4 // header + qname + qtype/qclass
	var b wire.Builder
	(&wire.EDNS{DOBit: true}).Encode(&b)
	expected := b.Bytes()
	if !bytes.Equal(q[headerEnd:], expected) {
		t.Errorf("BuildQuery trailing OPT differs from wire.EDNS.Encode:\n got = %x\nwant = %x",
			q[headerEnd:], expected)
	}
}
