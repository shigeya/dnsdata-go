package zone

import "sync"

// Registry maps RR types ([types.Type*] codes) to the [HandlerFactory]
// that builds their [RecordHandler]. A Registry is safe for concurrent
// use; the zero value is not ready to use, construct one with
// [NewRegistry].
//
// The package keeps one default Registry ([DefaultRegistry]), which
// [RegisterRRHandler], [RegisterHandlers], [ResourceRecord.Handler] and
// [ResourceRecord.WireBody] use; this matches dnsdata-js's
// register_rr_handler shape. Code that must not depend on, or change,
// process-wide state (the verifier, DESIGN.md MUST NOT 22) builds its
// own Registry and passes it to [ResourceRecord.HandlerFrom] and
// [ResourceRecord.WireBodyWith].
type Registry struct {
	mu        sync.RWMutex
	factories map[uint16]HandlerFactory
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[uint16]HandlerFactory{}}
}

// defaultRegistry backs [DefaultRegistry].
var defaultRegistry = NewRegistry()

// DefaultRegistry returns the package's default Registry, the one
// [RegisterRRHandler], [RegisterHandlers] and the registry-less methods
// of [ResourceRecord] use.
func DefaultRegistry() *Registry { return defaultRegistry }

// Register installs factory as the handler builder for RRs of rrtype,
// replacing any earlier one. A nil factory removes the registration.
func (r *Registry) Register(rrtype uint16, factory HandlerFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if factory == nil {
		delete(r.factories, rrtype)
		return
	}
	r.factories[rrtype] = factory
}

// Lookup returns the factory registered for rrtype, or nil.
func (r *Registry) Lookup(rrtype uint16) HandlerFactory {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.factories[rrtype]
}

// orDefault resolves a nil Registry to the default one.
func (r *Registry) orDefault() *Registry {
	if r == nil {
		return defaultRegistry
	}
	return r
}

// RegisterRRHandler installs factory as the handler builder for RRs of
// the given type in the default registry. Subsequent calls overwrite
// earlier ones; a nil factory removes the registration. Equivalent to
// DefaultRegistry().Register(rrtype, factory).
func RegisterRRHandler(rrtype uint16, factory HandlerFactory) {
	defaultRegistry.Register(rrtype, factory)
}

// handlerEntry is the handler cached on a [ResourceRecord] together
// with the Registry whose factory built it.
type handlerEntry struct {
	reg     *Registry
	handler RecordHandler
}
