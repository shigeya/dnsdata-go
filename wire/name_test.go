package wire_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/wire"
)

// Test vectors ported verbatim from dnsdata-js/.../dns_wire.spec.ts.
// The TypeScript test asserts that wire2domain_name(encode(x)) ==
// x.toLowerCase(); we mirror that.
var nameVector = []struct {
	name string
	wire []byte
}{
	{"xp.net.", []byte{0x02, 0x78, 0x70, 0x03, 0x6e, 0x65, 0x74, 0x00}},
	{"Z.ISI.ARPA.", []byte{0x01, 0x7a, 0x03, 0x69, 0x73, 0x69, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00}},
	{"FOO.ISI.ARPA.", []byte{0x03, 0x66, 0x6f, 0x6f, 0x03, 0x69, 0x73, 0x69, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00}},
	{"ARPA.", []byte{0x04, 0x61, 0x72, 0x70, 0x61, 0x00}},
	{"ARPA", []byte{0x04, 0x61, 0x72, 0x70, 0x61}},
	{"sh.wide.xx.jp.", []byte{0x02, 0x73, 0x68, 0x04, 0x77, 0x69, 0x64, 0x65, 0x02, 0x78, 0x78, 0x02, 0x6a, 0x70, 0x00}},
	{"ns.wide.xx.jp", []byte{0x02, 0x6e, 0x73, 0x04, 0x77, 0x69, 0x64, 0x65, 0x02, 0x78, 0x78, 0x02, 0x6a, 0x70}},
}

func TestDomainNameToWire(t *testing.T) {
	for _, tc := range nameVector {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wire.DomainNameToWire(tc.name)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalBytes(got, tc.wire) {
				t.Errorf("DomainNameToWire(%q) = % x, want % x", tc.name, got, tc.wire)
			}
		})
	}
}

func TestWireToDomainName(t *testing.T) {
	for _, tc := range nameVector {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wire.WireToDomainName(tc.wire)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := strings.ToLower(tc.name)
			if got != want {
				t.Errorf("WireToDomainName(% x) = %q, want %q", tc.wire, got, want)
			}
		})
	}
}

// TestDomainNameToWire_Underscore covers a deliberate deviation from the
// TypeScript source: `_dmarc.example.com.` must round-trip. The TS code
// uses `byte | 0x20` which corrupts 0x5F into 0x7F; we use proper ASCII
// tolower instead.
func TestDomainNameToWire_Underscore(t *testing.T) {
	const name = "_dmarc.example.com."
	encoded, err := wire.DomainNameToWire(name)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte{
		0x06, '_', 'd', 'm', 'a', 'r', 'c',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	if !equalBytes(encoded, want) {
		t.Errorf("encode = % x, want % x", encoded, want)
	}
	decoded, err := wire.WireToDomainName(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != name {
		t.Errorf("round-trip = %q, want %q", decoded, name)
	}
}

// TestDomainNameToWire_Canonical verifies RFC 4034 §6.2 canonical-form
// lowercasing on a label that mixes letters and digits.
func TestDomainNameToWire_Canonical(t *testing.T) {
	got, err := wire.DomainNameToWire("Example123.NET.")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte{
		0x0a, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '1', '2', '3',
		0x03, 'n', 'e', 't',
		0x00,
	}
	if !equalBytes(got, want) {
		t.Errorf("encode = % x, want % x", got, want)
	}
}

func TestDomainNameToWire_LabelTooLong(t *testing.T) {
	long := strings.Repeat("a", 64) + ".example."
	_, err := wire.DomainNameToWire(long)
	if !errors.Is(err, wire.ErrLabelTooLong) {
		t.Errorf("err = %v, want ErrLabelTooLong", err)
	}
}

func TestDomainNameToWire_NameTooLong(t *testing.T) {
	// 4 * 63 + 4 length octets + terminator = 256 octets
	var sb strings.Builder
	for range 4 {
		sb.WriteString(strings.Repeat("a", 63))
		sb.WriteByte('.')
	}
	_, err := wire.DomainNameToWire(sb.String())
	if !errors.Is(err, wire.ErrNameTooLong) {
		t.Errorf("err = %v, want ErrNameTooLong", err)
	}
}

func TestWireToDomainName_Compressed(t *testing.T) {
	// 0xC0 0x0C is a typical RFC 1035 §4.1.4 compression pointer.
	_, err := wire.WireToDomainName([]byte{0xC0, 0x0C})
	if !errors.Is(err, wire.ErrCompressed) {
		t.Errorf("err = %v, want ErrCompressed", err)
	}
}

func TestWireToDomainName_Truncated(t *testing.T) {
	// length byte says 4, but only 2 bytes follow
	_, err := wire.WireToDomainName([]byte{0x04, 'a', 'b'})
	if !errors.Is(err, wire.ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}

func TestDomainNameToWire_Empty(t *testing.T) {
	got, err := wire.DomainNameToWire("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("encode(\"\") = % x, want empty", got)
	}
}

func TestDomainNameToWire_Root(t *testing.T) {
	got, err := wire.DomainNameToWire(".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalBytes(got, []byte{0x00}) {
		t.Errorf("encode(\".\") = % x, want 00", got)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
