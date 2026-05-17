package types_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

var algorithmVector = []struct {
	code uint8
	str  string
}{
	{0, "DELETE"},
	{1, "RSAMD5"},
	{2, "DH"},
	{3, "DSA"},
	{5, "RSASHA1"},
	{6, "DSA-NSEC3-SHA1"},
	{7, "RSASHA1-NSEC3-SHA1"},
	{8, "RSASHA256"},
	{10, "RSASHA512"},
	{12, "ECC-GOST"},
	{13, "ECDSAP256SHA256"},
	{14, "ECDSAP384SHA384"},
	{15, "ED25519"},
	{16, "ED448"},
	{252, "INDIRECT"},
	{253, "PRIVATEDNS"},
	{254, "PRIVATEOID"},
}

func TestAlgorithmToString(t *testing.T) {
	for _, tc := range algorithmVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.AlgorithmToString(tc.code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.str {
				t.Errorf("AlgorithmToString(%d) = %q, want %q", tc.code, got, tc.str)
			}
		})
	}
}

func TestAlgorithmToString_Unknown(t *testing.T) {
	// 4 and 9 are unassigned in the IANA registry
	for _, c := range []uint8{4, 9, 11, 100} {
		_, err := types.AlgorithmToString(c)
		if !errors.Is(err, types.ErrUnknownAlgo) {
			t.Errorf("AlgorithmToString(%d) error = %v, want ErrUnknownAlgo", c, err)
		}
	}
}

func TestStringToAlgorithm(t *testing.T) {
	for _, tc := range algorithmVector {
		t.Run(tc.str, func(t *testing.T) {
			got, err := types.StringToAlgorithm(tc.str)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.code {
				t.Errorf("StringToAlgorithm(%q) = %d, want %d", tc.str, got, tc.code)
			}
		})
	}
}

func TestStringToAlgorithm_Unknown(t *testing.T) {
	_, err := types.StringToAlgorithm("XXX")
	if !errors.Is(err, types.ErrUnknownAlgo) {
		t.Errorf("StringToAlgorithm(\"XXX\") error = %v, want ErrUnknownAlgo", err)
	}
}

func TestAlgorithmSupported(t *testing.T) {
	supported := []uint8{5, 7, 8, 10, 13, 14, 15}
	for _, a := range supported {
		if !types.AlgorithmSupported(a) {
			t.Errorf("AlgorithmSupported(%d) = false, want true", a)
		}
	}
	unsupported := []uint8{0, 1, 3, 12, 16, 100}
	for _, a := range unsupported {
		if types.AlgorithmSupported(a) {
			t.Errorf("AlgorithmSupported(%d) = true, want false", a)
		}
	}
}
