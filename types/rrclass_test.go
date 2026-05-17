package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

var rrclassVector = []struct {
	code uint16
	str  string
}{
	{0, "INVALID"},
	{1, "IN"},
	{2, "UNALLOC_2"},
	{3, "CHAOS"},
	{4, "HS"},
	{254, "NONE"},
	{255, "ANY"},
}

func TestRRClassToString(t *testing.T) {
	for _, tc := range rrclassVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.RRClassToString(tc.code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.str {
				t.Errorf("RRClassToString(%d) = %q, want %q", tc.code, got, tc.str)
			}
		})
	}
}

func TestRRClassToString_Unknown(t *testing.T) {
	_, err := types.RRClassToString(999)
	if !errors.Is(err, types.ErrUnknownRRClass) {
		t.Errorf("RRClassToString(999) error = %v, want ErrUnknownRRClass", err)
	}
}

func TestStringToRRClass(t *testing.T) {
	for _, tc := range rrclassVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.StringToRRClass(tc.str)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.code {
				t.Errorf("StringToRRClass(%q) = %d, want %d", tc.str, got, tc.code)
			}
		})
	}
}

func TestStringToRRClass_Unknown(t *testing.T) {
	_, err := types.StringToRRClass("XXX")
	if !errors.Is(err, types.ErrUnknownRRClass) {
		t.Errorf("StringToRRClass(\"XXX\") error = %v, want ErrUnknownRRClass", err)
	}
}

func TestQClassValidForRequest(t *testing.T) {
	for _, c := range []uint16{1, 3, 4, 255} {
		if !types.QClassValidForRequest(c) {
			t.Errorf("QClassValidForRequest(%d) = false, want true", c)
		}
	}
	for _, c := range []uint16{0, 254, 999} {
		if types.QClassValidForRequest(c) {
			t.Errorf("QClassValidForRequest(%d) = true, want false", c)
		}
	}
}
