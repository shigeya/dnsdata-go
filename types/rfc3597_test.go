package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

// RFC 3597 §5: TYPEnnn / CLASSnnn generic mnemonics.

func TestStringToRRType_Generic(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
	}{
		{"TYPE65400", 65400},
		{"type65400", 65400},
		{"Type1", types.TypeA},
		{"TYPE0", 0},
		{"TYPE65535", 65535},
		{"TYPE52", types.TypeTLSA},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := types.StringToRRType(tc.in)
			if err != nil {
				t.Fatalf("StringToRRType(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("StringToRRType(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestStringToRRType_GenericRejects(t *testing.T) {
	for _, in := range []string{"TYPE", "TYPE65536", "TYPE-1", "TYPE1x", "TYPE 1", "TYPE+1"} {
		t.Run(in, func(t *testing.T) {
			if _, err := types.StringToRRType(in); !errors.Is(err, types.ErrUnknownRRType) {
				t.Errorf("StringToRRType(%q) error = %v, want ErrUnknownRRType", in, err)
			}
		})
	}
}

func TestStringToRRClass_Generic(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
	}{
		{"CLASS1", types.ClassIN},
		{"class3", types.ClassCHAOS},
		{"CLASS65280", 65280},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := types.StringToRRClass(tc.in)
			if err != nil {
				t.Fatalf("StringToRRClass(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("StringToRRClass(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
	if _, err := types.StringToRRClass("CLASS70000"); !errors.Is(err, types.ErrUnknownRRClass) {
		t.Errorf("StringToRRClass(CLASS70000) error = %v, want ErrUnknownRRClass", err)
	}
}

func TestRRTypeName(t *testing.T) {
	if got := types.RRTypeName(types.TypeTLSA); got != "TLSA" {
		t.Errorf("RRTypeName(TLSA) = %q", got)
	}
	if got := types.RRTypeName(65400); got != "TYPE65400" {
		t.Errorf("RRTypeName(65400) = %q, want TYPE65400", got)
	}
}

func TestRRClassName(t *testing.T) {
	if got := types.RRClassName(types.ClassIN); got != "IN" {
		t.Errorf("RRClassName(IN) = %q", got)
	}
	if got := types.RRClassName(65280); got != "CLASS65280" {
		t.Errorf("RRClassName(65280) = %q, want CLASS65280", got)
	}
}
