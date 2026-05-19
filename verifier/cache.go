package verifier

import (
	"sync"

	"github.com/shigeya/dnsdata-go/zone"
)

// Cache caches resolver responses keyed by (name, qtype).
//
// The verifier consults the cache before every Resolver.Query and
// stores successful responses back into it. Misses fall through to
// the underlying [Resolver]; errors from the resolver are NEVER
// cached.
//
// Implementations:
//
//   - MUST be safe for concurrent Get / Put from multiple goroutines.
//     A single [Verifier] is allowed to validate several names in
//     parallel; the chain walker itself is single-goroutine per
//     Validate call, but callers commonly fan out across many
//     validators that share one cache.
//   - MAY use any eviction / TTL policy they like. The verifier does
//     not inspect RR TTLs and does not call back into the cache to
//     refresh entries. Implementations that need TTL-aware eviction
//     should examine the records' [zone.ResourceRecord.TTL] field
//     themselves.
//   - MUST NOT mutate the slice or its element pointers after [Put]
//     returns. The verifier shares the same pointers with the
//     underlying [dnssec.Zone] and a future cache reader.
//
// Caching NODATA:
//
// A successful resolver response with zero records is a valid cache
// entry (it represents "this rrset is empty"). Implementations MUST
// store and return such entries the same as any other, and Get MUST
// signal "hit" via ok=true even when records is empty.
type Cache interface {
	// Get returns the cached records for (name, qtype). ok is false
	// when no entry is present; an empty slice with ok=true denotes
	// a cached NODATA response.
	Get(name string, qtype uint16) (records []*zone.ResourceRecord, ok bool)

	// Put stores records for (name, qtype). The verifier guarantees
	// it will not mutate the slice or its elements after the call;
	// implementations are free to retain the slice as-is.
	Put(name string, qtype uint16, records []*zone.ResourceRecord)
}

// MemoryCache is a process-local, unbounded [Cache] suitable for
// short-lived batch runs. Entries never expire; callers that need
// TTL-aware eviction should layer their own implementation around
// the [Cache] interface.
//
// The zero value is NOT ready to use; construct with [NewMemoryCache].
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[memoryCacheKey][]*zone.ResourceRecord
}

type memoryCacheKey struct {
	name  string
	qtype uint16
}

// NewMemoryCache returns an empty in-memory [Cache] safe for
// concurrent use.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: map[memoryCacheKey][]*zone.ResourceRecord{}}
}

// Get implements [Cache.Get].
func (c *MemoryCache) Get(name string, qtype uint16) ([]*zone.ResourceRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rrs, ok := c.entries[memoryCacheKey{name: name, qtype: qtype}]
	return rrs, ok
}

// Put implements [Cache.Put].
func (c *MemoryCache) Put(name string, qtype uint16, records []*zone.ResourceRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[memoryCacheKey{name: name, qtype: qtype}] = records
}

// Len returns the number of cached (name, qtype) pairs. Intended for
// tests and observability; not part of the [Cache] interface.
func (c *MemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
