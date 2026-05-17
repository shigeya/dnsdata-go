package wire_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/wire"
)

// Test cases ported from dnsdata-js/.../dns_wire_util.spec.ts.

func TestBuilder_AppendUint8(t *testing.T) {
	var b wire.Builder
	b.AppendUint8(0x42)
	if !equalBytes(b.Bytes(), []byte{0x42}) {
		t.Errorf("got % x, want 42", b.Bytes())
	}
}

func TestBuilder_AppendUint16(t *testing.T) {
	var b wire.Builder
	b.AppendUint16(0x0102)
	if !equalBytes(b.Bytes(), []byte{0x01, 0x02}) {
		t.Errorf("got % x, want 01 02", b.Bytes())
	}
}

func TestBuilder_AppendUint32(t *testing.T) {
	var b wire.Builder
	b.AppendUint32(0x01020304)
	if !equalBytes(b.Bytes(), []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("got % x, want 01 02 03 04", b.Bytes())
	}
}

func TestBuilder_AppendBytes(t *testing.T) {
	var b wire.Builder
	b.AppendBytes([]byte{0xAA, 0xBB})
	b.AppendUint8(0xCC)
	if !equalBytes(b.Bytes(), []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("got % x, want AA BB CC", b.Bytes())
	}
}

func TestBuilder_Len(t *testing.T) {
	var b wire.Builder
	if b.Len() != 0 {
		t.Errorf("initial Len = %d, want 0", b.Len())
	}
	b.AppendUint16(0x0001)
	if b.Len() != 2 {
		t.Errorf("after uint16 Len = %d, want 2", b.Len())
	}
	b.AppendUint32(0x00000001)
	if b.Len() != 6 {
		t.Errorf("after uint32 Len = %d, want 6", b.Len())
	}
}

// TestBuilder_RRSIGHeader exercises the typical RRSIG fixed-header
// layout (type, algorithm, labels, TTL) used by the dnssec_rr port.
func TestBuilder_RRSIGHeader(t *testing.T) {
	var b wire.Builder
	b.AppendUint16(1)     // type covered = A
	b.AppendUint8(8)      // algorithm = RSASHA256
	b.AppendUint8(2)      // labels
	b.AppendUint32(86400) // original TTL
	want := []byte{
		0x00, 0x01,
		0x08,
		0x02,
		0x00, 0x01, 0x51, 0x80,
	}
	if !equalBytes(b.Bytes(), want) {
		t.Errorf("got % x, want % x", b.Bytes(), want)
	}
}

func TestBuilder_Clone(t *testing.T) {
	var b wire.Builder
	b.AppendBytes([]byte{1, 2, 3})
	c := b.Clone()
	c[0] = 9 // mutating the clone must not affect the builder
	if b.Bytes()[0] != 1 {
		t.Errorf("Clone aliases Bytes; got %d, want 1", b.Bytes()[0])
	}
}

func TestCompareBytes(t *testing.T) {
	if wire.CompareBytes([]byte{1, 2, 3}, []byte{1, 2, 3}) != 0 {
		t.Errorf("equal arrays should compare 0")
	}
	if !(wire.CompareBytes([]byte{1, 2, 3}, []byte{1, 2, 4}) < 0) {
		t.Errorf("[1 2 3] should be < [1 2 4]")
	}
	if !(wire.CompareBytes([]byte{1, 2}, []byte{1, 2, 3}) < 0) {
		t.Errorf("shorter prefix should be less")
	}
}
