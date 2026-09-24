// Package memory is an in-memory authoritative server for a set of
// (signed) zones, usable as a verifier.Resolver.
//
// It answers the queries a validating resolver makes — answers with
// their RRSIGs, DNSKEY at each apex, DS from the parent side of a zone
// cut, referrals for delegations it does not hold, NODATA and NXDOMAIN
// with their NSEC proofs, CNAME, DNAME and wildcard synthesis — without
// any network. Together with dnssec/signer it lets a whole hierarchy,
// including a private root, be built and validated in a test:
// verifier.WithTrustAnchors takes the root's anchors from
// signer.RootAnchors, and verifier.WithClock pins the time.
//
// An [Authority] is immutable after [New] and safe for concurrent use;
// every response carries fresh copies of the records. NSEC3 proofs are
// not generated.
package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// ErrConfig reports an invalid [New] configuration.
var ErrConfig = errors.New("memory authority: configuration")

// Authority answers queries from the zones it was built with.
type Authority struct {
	zones  []*zoneIndex
	faults map[faultKey]uint8
}

type faultKey struct {
	name  string
	qtype uint16
}

type config struct {
	zones  []zoneSpec
	faults map[faultKey]uint8
}

type zoneSpec struct {
	apex string
	z    *zone.Zone
}

// Option configures [New].
type Option func(*config)

// WithZone serves z as the zone at apex. Every record of z must be at
// or below apex. The zone is indexed once by New; later changes to z
// are not seen.
func WithZone(apex string, z *zone.Zone) Option {
	return func(c *config) { c.zones = append(c.zones, zoneSpec{apex: apex, z: z}) }
}

// WithFault makes the authority answer (name, qtype) with rcode and no
// records, for negative tests (for example SERVFAIL = 2).
func WithFault(name string, qtype uint16, rcode uint8) Option {
	return func(c *config) { c.faults[faultKey{normalize(name), qtype}] = rcode }
}

// New builds an Authority. At least one zone is required; apexes must
// be fully qualified and distinct.
func New(opts ...Option) (*Authority, error) {
	c := &config{faults: map[faultKey]uint8{}}
	for _, opt := range opts {
		opt(c)
	}
	if len(c.zones) == 0 {
		return nil, fmt.Errorf("%w: no zones", ErrConfig)
	}
	a := &Authority{faults: c.faults}
	seen := map[string]bool{}
	for _, spec := range c.zones {
		if spec.z == nil || !strings.HasSuffix(spec.apex, ".") {
			return nil, fmt.Errorf("%w: zone %q needs a fully qualified apex and a zone", ErrConfig, spec.apex)
		}
		apex := normalize(spec.apex)
		if seen[apex] {
			return nil, fmt.Errorf("%w: zone %s given twice", ErrConfig, apex)
		}
		seen[apex] = true
		idx, err := newZoneIndex(apex, spec.z)
		if err != nil {
			return nil, err
		}
		a.zones = append(a.zones, idx)
	}
	return a, nil
}

// Query implements verifier.Resolver. The name is matched
// case-insensitively; a trailing dot is optional. A name outside every
// zone is answered with REFUSED.
func (a *Authority) Query(ctx context.Context, name string, qtype uint16) (resolver.Response, error) {
	if err := ctx.Err(); err != nil {
		return resolver.Response{}, err
	}
	name = normalize(name)
	if rcode, ok := a.faults[faultKey{name, qtype}]; ok {
		return resolver.Response{RCode: rcode}, nil
	}
	idx := a.zoneFor(name, qtype)
	if idx == nil {
		return resolver.Response{RCode: rcodeRefused}, nil
	}
	return idx.answer(name, qtype), nil
}

// zoneFor picks the deepest zone containing name. A DS query for a
// zone's apex is answered from the parent side of the cut instead.
func (a *Authority) zoneFor(name string, qtype uint16) *zoneIndex {
	var best *zoneIndex
	for _, idx := range a.zones {
		if !isAtOrBelow(name, idx.apex) {
			continue
		}
		if qtype == types.TypeDS && name == idx.apex && name != "." {
			continue
		}
		if best == nil || len(labels(idx.apex)) > len(labels(best.apex)) {
			best = idx
		}
	}
	return best
}
