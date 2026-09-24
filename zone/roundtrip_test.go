package zone_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

type rdataVector struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	RData string `json:"rdata"`
}

func loadRDataVectors(t *testing.T) []rdataVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "rdata_roundtrip.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []rdataVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return doc.Vectors
}

func registerAllHandlers() {
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
}

// wireBodyOf returns the RDATA octets (without RDLENGTH) of rr.
func wireBodyOf(t *testing.T, rr *zone.ResourceRecord) []byte {
	t.Helper()
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody(%q): %v", rr.Value, err)
	}
	out := b.Clone()
	if len(out) < 2 {
		t.Fatalf("WireBody(%q) wrote %d octets, want RDLENGTH + RDATA", rr.Value, len(out))
	}
	if n := int(out[0])<<8 | int(out[1]); n != len(out)-2 {
		t.Fatalf("WireBody(%q): RDLENGTH %d, body %d", rr.Value, n, len(out)-2)
	}
	return out[2:]
}

// TestRDataRoundTrip is the C-2 acceptance property: wire →
// RDataToString → NewResourceRecord → WireBody reproduces the RDATA,
// and so does the RFC 3597 generic form of the same octets.
func TestRDataRoundTrip(t *testing.T) {
	registerAllHandlers()
	for _, v := range loadRDataVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			rdata, err := hex.DecodeString(v.RData)
			if err != nil {
				t.Fatalf("vector hex: %v", err)
			}
			pres, err := wire.RDataToString(rdata, v.Type, rdata, 0)
			if err != nil {
				t.Fatalf("RDataToString: %v", err)
			}
			for _, value := range []string{pres, wire.FormatGenericRData(rdata)} {
				rr, err := zone.NewResourceRecord("example.com.", 300, types.ClassIN, v.Type, value)
				if err != nil {
					t.Fatalf("NewResourceRecord(%q): %v", value, err)
				}
				if got := wireBodyOf(t, rr); !bytes.Equal(got, rdata) {
					t.Errorf("value %q:\n got %x\nwant %x", value, got, rdata)
				}
			}
		})
	}
}

func TestParseGenericRData(t *testing.T) {
	cases := []struct {
		in        string
		want      string
		isGeneric bool
		wantErr   bool
	}{
		{`\# 4 0a000001`, "0a000001", true, false},
		{`\# 4 0a00 0001`, "0a000001", true, false},
		{`\# 0`, "", true, false},
		{`\# 3 0a000001`, "", true, true},
		{`\# 4 0a0000zz`, "", true, true},
		{`\#`, "", true, true},
		{`\# x 00`, "", true, true},
		{`\# 70000 00`, "", true, true},
		{`10.0.0.1`, "", false, false},
		{`"\# 4 0a000001"`, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, isGeneric, err := zone.ParseGenericRData(tc.in)
			if isGeneric != tc.isGeneric {
				t.Errorf("isGeneric = %v, want %v", isGeneric, tc.isGeneric)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Errorf("rdata = %x, want %s", got, tc.want)
			}
		})
	}
}

func TestWireBody_GenericLengthMismatchIsError(t *testing.T) {
	rr, err := zone.NewResourceRecord("x.example.", 60, "IN", "TYPE65400", `\# 5 00`)
	if err != nil {
		t.Fatal(err)
	}
	var b wire.Builder
	if err := rr.WireBody(&b); err == nil {
		t.Fatal("WireBody accepted a length mismatch")
	}
}

func TestHandler_FromGenericTLSA(t *testing.T) {
	registerAllHandlers()
	rr, err := zone.NewResourceRecord("_443._tcp.example.", 60, "IN", "TLSA", `\# 5 030101abcd`)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := rr.Handler().(*zone.TLSA)
	if !ok {
		t.Fatalf("Handler() = %T, want *zone.TLSA", rr.Handler())
	}
	if h.Usage != 3 || h.Selector != 1 || h.MatchingType != 1 || hex.EncodeToString(h.CertificateAssociationData) != "abcd" {
		t.Errorf("TLSA = %+v", h)
	}
}

func TestHandler_FromGenericSVCB(t *testing.T) {
	registerAllHandlers()
	rr, err := zone.NewResourceRecordFromRData("example.", 60, types.ClassIN, types.TypeHTTPS,
		mustHex(t, "00010000010003026832"))
	if err != nil {
		t.Fatal(err)
	}
	h, ok := rr.Handler().(*zone.SVCB)
	if !ok {
		t.Fatalf("Handler() = %T, want *zone.SVCB", rr.Handler())
	}
	if h.Priority != 1 || h.Target != "." || len(h.Params) != 1 || h.Params[0].Key != zone.SvcKeyAlpn {
		t.Errorf("SVCB = %+v", h)
	}
}

func TestHandler_FromGenericDNSKEY(t *testing.T) {
	registerAllHandlers()
	rr, err := zone.NewResourceRecordFromRData("example.", 60, types.ClassIN, types.TypeDNSKEY,
		mustHex(t, "0101030d00010203"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rr.Handler().(*dnssec.DNSKey); !ok {
		t.Fatalf("Handler() = %T, want *dnssec.DNSKey", rr.Handler())
	}
}

func TestTXTStrings(t *testing.T) {
	generic, err := zone.NewResourceRecordFromRData("example.", 60, types.ClassIN, types.TypeTXT,
		mustHex(t, "0568656c6c6f00"))
	if err != nil {
		t.Fatal(err)
	}
	pres, err := zone.NewResourceRecord("example.", 60, "IN", "TXT", `"hello" ""`)
	if err != nil {
		t.Fatal(err)
	}
	for _, rr := range []*zone.ResourceRecord{generic, pres} {
		got, err := rr.TXTStrings()
		if err != nil {
			t.Fatalf("TXTStrings(%q): %v", rr.Value, err)
		}
		if len(got) != 2 || got[0] != "hello" || got[1] != "" {
			t.Errorf("TXTStrings(%q) = %q", rr.Value, got)
		}
	}
	a, _ := zone.NewResourceRecord("example.", 60, "IN", "A", "192.0.2.1")
	if _, err := a.TXTStrings(); err == nil {
		t.Error("TXTStrings on A: want error")
	}
	bad, _ := zone.NewResourceRecordFromRData("example.", 60, types.ClassIN, types.TypeTXT, mustHex(t, "05ab"))
	if _, err := bad.TXTStrings(); err == nil {
		t.Error("TXTStrings on truncated string: want error")
	}
}

func TestNewResourceRecordFromRData_TooLong(t *testing.T) {
	if _, err := zone.NewResourceRecordFromRData("x.", 0, types.ClassIN, 65400, make([]byte, 0x10000)); err == nil {
		t.Error("want error for RDATA over 65535 octets")
	}
}

func TestString_UnknownTypeAndClass(t *testing.T) {
	rr, err := zone.NewResourceRecord("x.example.", 60, "CLASS65280", "TYPE65400", `\# 0`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rr.String(), `x.example. 60 CLASS65280 TYPE65400 \# 0`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
