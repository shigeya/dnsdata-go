package zone_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

func TestReadStringStrict_Accepts(t *testing.T) {
	registerAllHandlers()
	text := `$ORIGIN example.test.
$TTL 3600
@        IN  SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@           NS  ns1.example.test.
ns1      60 IN A 192.0.2.1
         IN 60 AAAA 2001:db8::1   ; class before TTL, inherited owner
key      TYPE65400 \# 4 ( 0102
                         0304 )
txt      CLASS1 TXT "a;b" "c"      ; semicolon inside quotes is data
_443._tcp TLSA 3 1 1 00112233
`
	var z zone.Zone
	if err := z.ReadStringStrict(text); err != nil {
		t.Fatalf("ReadStringStrict: %v", err)
	}
	checks := []struct {
		name  string
		typ   uint16
		ttl   uint32
		value string
	}{
		{"example.test.", types.TypeSOA, 3600, "ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300"},
		{"example.test.", types.TypeNS, 3600, "ns1.example.test."},
		{"ns1.example.test.", types.TypeA, 60, "192.0.2.1"},
		{"ns1.example.test.", types.TypeAAAA, 60, "2001:db8::1"},
		{"key.example.test.", 65400, 3600, `\# 4 0102 0304`},
		{"txt.example.test.", types.TypeTXT, 3600, `"a;b" "c"`},
		{"_443._tcp.example.test.", types.TypeTLSA, 3600, "3 1 1 00112233"},
	}
	for _, c := range checks {
		rr := z.FindRR(c.name, c.typ)
		if rr == nil {
			t.Errorf("missing %s/%s", c.name, types.RRTypeName(c.typ))
			continue
		}
		if rr.TTL != c.ttl || rr.Value != c.value {
			t.Errorf("%s/%s = ttl %d value %q, want ttl %d value %q",
				c.name, types.RRTypeName(c.typ), rr.TTL, rr.Value, c.ttl, c.value)
		}
	}
	strs, err := z.FindRR("txt.example.test.", types.TypeTXT).TXTStrings()
	if err != nil || len(strs) != 2 || strs[0] != "a;b" {
		t.Errorf("TXTStrings = %q, %v", strs, err)
	}
}

func TestReadStringStrict_Errors(t *testing.T) {
	registerAllHandlers()
	cases := []struct {
		name     string
		text     string
		wantLine int
	}{
		{"unknown type", "$ORIGIN example.test.\n$TTL 60\nok A 192.0.2.1\nbad NOSUCHTYPE 1 2 3\n", 4},
		{"generic length mismatch", "$TTL 60\nx.example. TYPE65400 \\# 3 0102\n", 2},
		{"relative owner without origin", "$TTL 60\nx A 192.0.2.1\n", 2},
		{"missing TTL", "x.example. A 192.0.2.1\n", 1},
		{"malformed rdata", "$TTL 60\nx.example. A not-an-address\n", 2},
		{"missing rdata", "$TTL 60\nx.example. A\n", 2},
		{"type without encoder", "$TTL 60\nx.example. OPT 00\n", 2},
		{"unsupported directive", "$INCLUDE other.zone\n", 1},
		{"inherited owner with none before", "$TTL 60\n  A 192.0.2.1\n", 2},
		{"unclosed parenthesis", "$TTL 60\nx.example. TXT ( \"a\"\n\"b\"\n", 2},
		{"bad TTL directive", "$TTL forever\n", 1},
		{"bad owner", "$TTL 60\nx..example. A 192.0.2.1\n", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var z zone.Zone
			err := z.ReadStringStrict(tc.text)
			var pe *zone.ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *zone.ParseError", err)
			}
			if pe.Line != tc.wantLine {
				t.Errorf("Line = %d, want %d (%v)", pe.Line, tc.wantLine, err)
			}
			if !errors.Is(err, zone.ErrPresentationFormat) && !errors.Is(err, zone.ErrRDataFormat) {
				t.Errorf("err = %v, want ErrPresentationFormat or ErrRDataFormat", err)
			}
		})
	}
}

func TestReadStringStrict_LeavesZoneUntouchedOnError(t *testing.T) {
	var z zone.Zone
	if _, err := z.AddRRFromParts("keep.example.", 60, "IN", "A", "192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	if err := z.ReadStringStrict("$TTL 60\nnew.example. A 192.0.2.1\nbad.example. NOPE x\n"); err == nil {
		t.Fatal("want error")
	}
	if n := len(z.AllRecords()); n != 1 {
		t.Errorf("zone has %d records after failed strict read, want 1", n)
	}
}

// The lenient reader keeps dropping the same line silently (existing
// behaviour); the strict reader is what surfaces it.
func TestReadString_StillLenient(t *testing.T) {
	var z zone.Zone
	if err := z.ReadString("$TTL 60\nbad.example. NOPE x\nok.example. A 192.0.2.1\n"); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if len(z.AllRecords()) != 1 {
		t.Errorf("records = %d, want 1", len(z.AllRecords()))
	}
}

func TestReadString_AcceptsGenericType(t *testing.T) {
	var z zone.Zone
	if err := z.ReadString("$TTL 60\nkey.example. TYPE65400 \\# 2 abcd\n"); err != nil {
		t.Fatal(err)
	}
	rr := z.FindRR("key.example.", 65400)
	if rr == nil {
		t.Fatal("TYPE65400 line dropped")
	}
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil || len(b.Clone()) != 4 {
		t.Errorf("WireBody = %x, %v", b.Clone(), err)
	}
}
