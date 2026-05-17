package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

// rrtypeVector extends the dns_type_table.spec.ts vector to cover every
// RR type that has a named constant in rrtype.go.
var rrtypeVector = []struct {
	code uint16
	str  string
}{
	{0, "INVALID"},
	{1, "A"},
	{2, "NS"},
	{5, "CNAME"},
	{6, "SOA"},
	{12, "PTR"},
	{13, "HINFO"},
	{15, "MX"},
	{16, "TXT"},
	{17, "RP"},
	{28, "AAAA"},
	{29, "LOC"},
	{33, "SRV"},
	{35, "NAPTR"},
	{37, "CERT"},
	{39, "DNAME"},
	{41, "OPT"},
	{43, "DS"},
	{44, "SSHFP"},
	{46, "RRSIG"},
	{47, "NSEC"},
	{48, "DNSKEY"},
	{50, "NSEC3"},
	{51, "NSEC3PARAM"},
	{52, "TLSA"},
	{53, "SMIMEA"},
	{59, "CDS"},
	{60, "CDNSKEY"},
	{61, "OPENPGPKEY"},
	{62, "CSYNC"},
	{64, "SVCB"},
	{65, "HTTPS"},
	{108, "EUI48"},
	{109, "EUI64"},
	{256, "URI"},
	{257, "CAA"},
}

func TestRRTypeToString(t *testing.T) {
	for _, tc := range rrtypeVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.RRTypeToString(tc.code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.str {
				t.Errorf("RRTypeToString(%d) = %q, want %q", tc.code, got, tc.str)
			}
		})
	}
}

func TestRRTypeToString_Unknown(t *testing.T) {
	_, err := types.RRTypeToString(999)
	if !errors.Is(err, types.ErrUnknownRRType) {
		t.Errorf("RRTypeToString(999) error = %v, want ErrUnknownRRType", err)
	}
}

func TestStringToRRType(t *testing.T) {
	for _, tc := range rrtypeVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.StringToRRType(tc.str)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.code {
				t.Errorf("StringToRRType(%q) = %d, want %d", tc.str, got, tc.code)
			}
		})
	}
}

func TestStringToRRType_Unknown(t *testing.T) {
	_, err := types.StringToRRType("XXX")
	if !errors.Is(err, types.ErrUnknownRRType) {
		t.Errorf("StringToRRType(\"XXX\") error = %v, want ErrUnknownRRType", err)
	}
}

func TestQTypeValidForRequest(t *testing.T) {
	valid := []uint16{1, 2, 5, 6, 12, 16, 28, 33, 35, 43, 46, 47, 48, 50, 256}
	for _, c := range valid {
		if !types.QTypeValidForRequest(c) {
			t.Errorf("QTypeValidForRequest(%d) = false, want true", c)
		}
	}
	// 0 = INVALID, 3/4 = MD/MF (obsolete), 999 = unassigned
	invalid := []uint16{0, 999, 3, 4}
	for _, c := range invalid {
		if types.QTypeValidForRequest(c) {
			t.Errorf("QTypeValidForRequest(%d) = true, want false", c)
		}
	}
}
