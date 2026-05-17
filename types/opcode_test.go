package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

var opcodeVector = []struct {
	code uint8
	str  string
}{
	{0, "Query"},
	{1, "IQuery"},
	{2, "Status"},
	{4, "Notify"},
	{5, "Update"},
}

func TestOpCodeToString(t *testing.T) {
	for _, tc := range opcodeVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.OpCodeToString(tc.code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.str {
				t.Errorf("OpCodeToString(%d) = %q, want %q", tc.code, got, tc.str)
			}
		})
	}
}

func TestOpCodeToString_Unknown(t *testing.T) {
	// opcode 3 is reserved
	_, err := types.OpCodeToString(3)
	if !errors.Is(err, types.ErrUnknownOpCode) {
		t.Errorf("OpCodeToString(3) error = %v, want ErrUnknownOpCode", err)
	}
}

func TestStringToOpCode(t *testing.T) {
	for _, tc := range opcodeVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.StringToOpCode(tc.str)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.code {
				t.Errorf("StringToOpCode(%q) = %d, want %d", tc.str, got, tc.code)
			}
		})
	}
}

func TestStringToOpCode_Unknown(t *testing.T) {
	_, err := types.StringToOpCode("XXX")
	if !errors.Is(err, types.ErrUnknownOpCode) {
		t.Errorf("StringToOpCode(\"XXX\") error = %v, want ErrUnknownOpCode", err)
	}
}
