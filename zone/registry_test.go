package zone_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Types far outside the assigned range, distinct from the ones the
// other handler tests register in the default registry.
const (
	regTypeA uint16 = 65520
	regTypeB uint16 = 65521
)

// otherHandler is a second handler type, so a test can tell which
// registry's factory built a handler.
type otherHandler struct{ fakeHandler }

func fakeFactory(calls *int32) zone.HandlerFactory {
	return func(_ *zone.ResourceRecord, value string) zone.RecordHandler {
		atomic.AddInt32(calls, 1)
		return &fakeHandler{value: value}
	}
}

func otherFactory(_ *zone.ResourceRecord, value string) zone.RecordHandler {
	return &otherHandler{fakeHandler{value: value + "!"}}
}

func TestRegistry_IsolatedFromDefault(t *testing.T) {
	var calls int32
	reg := zone.NewRegistry()
	reg.Register(regTypeA, fakeFactory(&calls))

	if zone.DefaultRegistry().Lookup(regTypeA) != nil {
		t.Fatal("registering into a new Registry reached the default registry")
	}
	rr := newRR(t, "example.com.", 60, "IN", regTypeA, "hello")
	if h := rr.Handler(); h != nil {
		t.Errorf("Handler() through the default registry = %T, want nil", h)
	}
	if _, ok := rr.HandlerFrom(reg).(*fakeHandler); !ok {
		t.Errorf("HandlerFrom(reg) = %T, want *fakeHandler", rr.HandlerFrom(reg))
	}
}

func TestRegistry_HandlerCachedPerRegistry(t *testing.T) {
	var calls int32
	regA, regB := zone.NewRegistry(), zone.NewRegistry()
	regA.Register(regTypeA, fakeFactory(&calls))
	regB.Register(regTypeA, otherFactory)
	rr := newRR(t, "example.com.", 60, "IN", regTypeA, "hello")

	h := rr.HandlerFrom(regA)
	if rr.HandlerFrom(regA) != h {
		t.Error("HandlerFrom(regA) not cached")
	}
	if _, ok := rr.HandlerFrom(regB).(*otherHandler); !ok {
		t.Errorf("HandlerFrom(regB) = %T, want *otherHandler (a handler from regA leaked)", rr.HandlerFrom(regB))
	}
	if _, ok := rr.HandlerFrom(regA).(*fakeHandler); !ok {
		t.Errorf("HandlerFrom(regA) after regB = %T, want *fakeHandler", rr.HandlerFrom(regA))
	}
}

func TestRegistry_WireBodyWithUsesTheRegistry(t *testing.T) {
	reg := zone.NewRegistry()
	reg.Register(regTypeA, otherFactory)
	rr := newRR(t, "example.com.", 60, "IN", regTypeA, "hi")

	var b wire.Builder
	if err := rr.WireBodyWith(reg, &b); err != nil {
		t.Fatalf("WireBodyWith: %v", err)
	}
	if got := string(b.Bytes()[2:]); got != "hi!" {
		t.Errorf("WireBodyWith wrote %q, want %q", got, "hi!")
	}
	var d wire.Builder
	if err := rr.WireBody(&d); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	if len(d.Bytes()) != 0 {
		t.Errorf("WireBody through the default registry wrote %d octets, want 0", len(d.Bytes()))
	}
}

func TestRegistry_RegisterNilRemoves(t *testing.T) {
	reg := zone.NewRegistry()
	reg.Register(regTypeA, otherFactory)
	reg.Register(regTypeA, nil)
	if reg.Lookup(regTypeA) != nil {
		t.Error("Register(nil) did not remove the factory")
	}
}

func TestRegistry_NilMeansDefault(t *testing.T) {
	zone.RegisterRRHandler(regTypeB, otherFactory)
	t.Cleanup(func() { zone.RegisterRRHandler(regTypeB, nil) })
	rr := newRR(t, "example.com.", 60, "IN", regTypeB, "x")
	if rr.HandlerFrom(nil) != rr.Handler() {
		t.Error("HandlerFrom(nil) differs from Handler()")
	}
}

func TestRegisterHandlersInto_LeavesDefaultAlone(t *testing.T) {
	reg := zone.NewRegistry()
	zone.RegisterHandlersInto(reg)
	if reg.Lookup(types.TypeTLSA) == nil || reg.Lookup(types.TypeSVCB) == nil {
		t.Error("RegisterHandlersInto did not install the zone handlers")
	}
	if reg.Lookup(types.TypeDNSKEY) != nil {
		t.Error("RegisterHandlersInto installed a DNSSEC handler")
	}
}

// TestRegistry_ConcurrentUse is meant for -race: records shared by
// goroutines that use different registries.
func TestRegistry_ConcurrentUse(t *testing.T) {
	regA, regB := zone.NewRegistry(), zone.NewRegistry()
	var calls int32
	regA.Register(regTypeA, fakeFactory(&calls))
	regB.Register(regTypeA, otherFactory)
	rr := newRR(t, "example.com.", 60, "IN", regTypeA, "v")

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reg := regA
			if i%2 == 1 {
				reg = regB
				reg.Register(regTypeB, otherFactory)
			}
			for range 100 {
				var b wire.Builder
				if err := rr.WireBodyWith(reg, &b); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
