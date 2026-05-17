package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

var rcodeVector = []struct {
	code uint16
	str  string
}{
	{0, "NOERROR"},
	{1, "FORMERR"},
	{2, "SERVFAIL"},
	{3, "NXDOMAIN"},
	{4, "NOTIMPL"},
	{5, "REFUSED"},
	{6, "YXDOMAIN"},
	{7, "YXRRSET"},
	{8, "NXRRSET"},
	{9, "NOTAUTH"},
	{10, "NOTZONE"},
	{16, "BADVERS/SIG"},
	{17, "BADKEY"},
	{18, "BADTIME"},
}

func TestRCodeToString(t *testing.T) {
	for _, tc := range rcodeVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.RCodeToString(tc.code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.str {
				t.Errorf("RCodeToString(%d) = %q, want %q", tc.code, got, tc.str)
			}
		})
	}
}

func TestRCodeToString_Unknown(t *testing.T) {
	// rcode 11 is unassigned
	_, err := types.RCodeToString(11)
	if !errors.Is(err, types.ErrUnknownRCode) {
		t.Errorf("RCodeToString(11) error = %v, want ErrUnknownRCode", err)
	}
}

func TestStringToRCode(t *testing.T) {
	for _, tc := range rcodeVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.StringToRCode(tc.str)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.code {
				t.Errorf("StringToRCode(%q) = %d, want %d", tc.str, got, tc.code)
			}
		})
	}
}

func TestStringToRCode_Unknown(t *testing.T) {
	_, err := types.StringToRCode("XXX")
	if !errors.Is(err, types.ErrUnknownRCode) {
		t.Errorf("StringToRCode(\"XXX\") error = %v, want ErrUnknownRCode", err)
	}
}
