package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

// While the OPKEY type value is not allocated, nothing hands out a
// number for it: OPKEYType fails, the mnemonic does not parse, and type
// 0 stays INVALID and is not a valid qtype.

func TestOPKEYType_Unallocated(t *testing.T) {
	got, err := types.OPKEYType()
	if !errors.Is(err, types.ErrOPKEYTypeUnallocated) {
		t.Fatalf("OPKEYType() = %d, %v; want ErrOPKEYTypeUnallocated", got, err)
	}
	if got != 0 {
		t.Errorf("OPKEYType() value = %d, want 0 with the error", got)
	}
}

func TestStringToRRType_OPKEYUnallocated(t *testing.T) {
	got, err := types.StringToRRType(types.OPKEYMnemonic)
	if !errors.Is(err, types.ErrOPKEYTypeUnallocated) {
		t.Fatalf("StringToRRType(OPKEY) = %d, %v; want ErrOPKEYTypeUnallocated", got, err)
	}
	if !errors.Is(err, types.ErrUnknownRRType) {
		t.Errorf("error %v does not also wrap ErrUnknownRRType", err)
	}
}

func TestOPKEYUnallocated_TypeZeroUnchanged(t *testing.T) {
	name, err := types.RRTypeToString(0)
	if err != nil || name != "INVALID" {
		t.Errorf("RRTypeToString(0) = %q, %v; want INVALID", name, err)
	}
	if types.QTypeValidForRequest(0) {
		t.Error("QTypeValidForRequest(0) = true, want false")
	}
}
