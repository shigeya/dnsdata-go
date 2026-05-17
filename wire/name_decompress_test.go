package wire_test

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/wire"
)

func TestParseDomainName_Uncompressed(t *testing.T) {
	// "example.com." encoded uncompressed = 7 example 3 com 0
	msg := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	got, next, err := wire.ParseDomainName(msg, 0)
	if err != nil {
		t.Fatalf("ParseDomainName: %v", err)
	}
	if got != "example.com." {
		t.Errorf("name = %q, want example.com.", got)
	}
	if next != len(msg) {
		t.Errorf("next = %d, want %d", next, len(msg))
	}
}

func TestParseDomainName_Root(t *testing.T) {
	msg := []byte{0x00, 0x42, 0x42}
	got, next, err := wire.ParseDomainName(msg, 0)
	if err != nil {
		t.Fatalf("ParseDomainName: %v", err)
	}
	if got != "." {
		t.Errorf("name = %q, want .", got)
	}
	if next != 1 {
		t.Errorf("next = %d, want 1", next)
	}
}

func TestParseDomainName_PointerToEarlier(t *testing.T) {
	// "example.com." at offset 0, then "www" + pointer to offset 0 at
	// offset 13.
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // offset 0..12
		3, 'w', 'w', 'w', 0xC0, 0x00, // offset 13..18 (pointer = 0)
	}
	got, next, err := wire.ParseDomainName(msg, 13)
	if err != nil {
		t.Fatalf("ParseDomainName: %v", err)
	}
	if got != "www.example.com." {
		t.Errorf("name = %q", got)
	}
	if next != 19 {
		t.Errorf("next = %d, want 19", next)
	}
}

func TestParseDomainName_RejectsForwardPointer(t *testing.T) {
	// Pointer points at itself.
	msg := []byte{0xC0, 0x00}
	_, _, err := wire.ParseDomainName(msg, 0)
	if !errors.Is(err, wire.ErrPointerForward) {
		t.Errorf("err = %v, want ErrPointerForward", err)
	}
}

func TestParseDomainName_RejectsLoop(t *testing.T) {
	// A pointer at offset 5 pointing to offset 0; the name at offset 0
	// starts with a label, then jumps forward. We need a backward loop.
	// Construct: offset 0 = pointer to 2, offset 2 = pointer to 0 — both
	// "earlier" relative to their position. Wait: offset 2's pointer to
	// 0 IS earlier. Offset 0's pointer to 2 is FORWARD (rejected).
	// Easier: offset 4 = pointer to 0, offset 0..1 = label "a" (1 byte).
	// Hmm — for a loop, we need two pointers that each point earlier
	// than themselves but still create a cycle, which is impossible
	// with the "must point earlier" rule. So ErrPointerLoop is
	// actually only reachable via excessive hops. We exercise that
	// by chaining 33 pointers, each pointing to the previous slot.
	//
	// Build: 32 pointers, each (i+2) pointing to (i)... pos i to i+1
	// is a pointer to i-2. The chain unwinds correctly though.
	// Easier still: visited-set hits when two pointers share a target.
	// Construct: offset 0 = 0x00 (root); offset 1..2 = pointer to 0;
	// offset 3..4 = pointer to 0. Start parsing at offset 3 → next
	// pointer to 0, follow there, see 0 → done. No revisit.
	//
	// A genuine revisit requires forward pointers, which we reject.
	// The visited set therefore guards only the conservative
	// "pointer immediately after a pointer to itself" pathological
	// case. Smoke-test the hop cap instead by chaining pointers.
	const n = 60
	msg := make([]byte, 1+2*n)
	msg[0] = 0 // root at offset 0
	for i := 0; i < n; i++ {
		off := 1 + 2*i
		// pointer to the previous pointer (or root for i=0)
		var target int
		if i == 0 {
			target = 0
		} else {
			target = 1 + 2*(i-1)
		}
		msg[off] = 0xC0 | byte(target>>8)
		msg[off+1] = byte(target)
	}
	// Start parsing the deepest pointer.
	_, _, err := wire.ParseDomainName(msg, 1+2*(n-1))
	if err == nil {
		t.Fatal("expected pointer-loop / hop-cap error, got nil")
	}
	if !errors.Is(err, wire.ErrPointerLoop) {
		t.Errorf("err = %v, want wrapped ErrPointerLoop", err)
	}
}

func TestParseDomainName_RejectsLabelTooLong(t *testing.T) {
	msg := []byte{64, 'a'} // length byte > 63 (and not a pointer)
	_, _, err := wire.ParseDomainName(msg, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestParseDomainName_RejectsTruncatedLabel(t *testing.T) {
	msg := []byte{5, 'a', 'b'} // label says 5 bytes but only 2 follow
	_, _, err := wire.ParseDomainName(msg, 0)
	if !errors.Is(err, wire.ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}

func TestParseDomainName_OutOfBoundsOffset(t *testing.T) {
	msg := []byte{0x00}
	_, _, err := wire.ParseDomainName(msg, 5)
	if !errors.Is(err, wire.ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}
