package zone_test

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// fakeHandler exercises the RegisterRRHandler / Handler() / WireBody()
// dispatch path. The future dnssec/ port will register real handlers via
// the same surface, so we want this plumbing covered.
type fakeHandler struct {
	value string
}

func (h *fakeHandler) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(len(h.value)))
	b.AppendBytes([]byte(h.value))
	return nil
}

func (h *fakeHandler) Clone() zone.RecordHandler { return &fakeHandler{value: h.value} }

// We use an RR type far outside the IANA-assigned range we expose to
// avoid colliding with built-in encoders.
const fakeRRType uint16 = 65530

func TestRegisterRRHandler_Dispatches(t *testing.T) {
	var called int32
	zone.RegisterRRHandler(fakeRRType, func(rr *zone.ResourceRecord, value string) zone.RecordHandler {
		atomic.AddInt32(&called, 1)
		return &fakeHandler{value: value}
	})

	rr, err := zone.NewResourceRecord("example.com.", 60, "IN", fakeRRType, "hello")
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}

	// First Handler() call constructs (and caches) the handler.
	h := rr.Handler()
	if h == nil {
		t.Fatalf("Handler returned nil")
	}
	// Second call must reuse the cached handler — factory not re-invoked.
	if rr.Handler() != h {
		t.Errorf("Handler() not cached")
	}
	if got := atomic.LoadInt32(&called); got != 1 {
		t.Errorf("factory invocations = %d, want 1", got)
	}

	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	got := b.Bytes()
	if int(got[1]) != len("hello") {
		t.Errorf("rdlength = %d, want %d", got[1], len("hello"))
	}
}

func TestNewResourceRecord_UnknownClassReturnsError(t *testing.T) {
	_, err := zone.NewResourceRecord("example.com.", 60, "XX", "A", "1.2.3.4")
	if !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestNewResourceRecord_UnknownTypeReturnsError(t *testing.T) {
	_, err := zone.NewResourceRecord("example.com.", 60, "IN", "BOGUS", "x")
	if !errors.Is(err, zone.ErrPresentationFormat) {
		t.Errorf("err = %v, want ErrPresentationFormat", err)
	}
}

func TestWireBody_MalformedAReturnsError(t *testing.T) {
	rr := newRR(t, "example.com.", 60, "IN", "A", "not-an-ip")
	var b wire.Builder
	err := rr.WireBody(&b)
	if !errors.Is(err, zone.ErrRDataFormat) {
		t.Errorf("err = %v, want ErrRDataFormat", err)
	}
}

func TestWireBody_MalformedMXReturnsError(t *testing.T) {
	// MX requires "<pref> <exchange>" with a numeric preference.
	rr := newRR(t, "example.com.", 60, "IN", "MX", "no-pref-or-exchange")
	var b wire.Builder
	err := rr.WireBody(&b)
	if !errors.Is(err, zone.ErrRDataFormat) {
		t.Errorf("err = %v, want ErrRDataFormat", err)
	}
}

func TestWireBody_UnsupportedTypeIsNoOp(t *testing.T) {
	// HINFO (13) has no built-in encoder and no registered handler.
	rr := newRR(t, "example.com.", 60, "IN", "HINFO", "Linux x86_64")
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	if got := len(b.Bytes()); got != 0 {
		t.Errorf("emitted %d bytes for unsupported type, want 0", got)
	}
}

func TestString_UnknownTypeFallback(t *testing.T) {
	// Construct an RR with an unassigned-by-IANA type code; String() must
	// fall back to TYPEnnn instead of returning an error.
	rr, err := zone.NewResourceRecord("example.com.", 60, uint16(999), uint16(999), "x")
	if err != nil {
		t.Fatalf("NewResourceRecord: %v", err)
	}
	s := rr.String()
	if !strings.Contains(s, "CLASS999") || !strings.Contains(s, "TYPE999") {
		t.Errorf("got %q, want CLASS999 / TYPE999 fallback", s)
	}
}
