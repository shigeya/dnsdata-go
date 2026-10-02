package signer

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// NSEC3Options selects an NSEC3 chain (RFC 5155) in place of NSEC. The
// zero value is the RFC 9276 §3.1 recommendation: no additional
// iterations, no salt, no opt-out.
type NSEC3Options struct {
	Iterations uint16
	Salt       []byte
	// OptOut leaves unsigned delegations out of the chain and sets the
	// opt-out flag on every NSEC3 (RFC 5155 §6).
	OptOut bool
}

const (
	nsec3HashSHA1      = 1    // RFC 5155 §11, the only defined algorithm
	nsec3FlagOptOut    = 0x01 // RFC 5155 §3.1.2.1
	maxNSEC3SaltLength = 255
)

// base32Hex is the RFC 4648 §7 alphabet of NSEC3 owner labels.
var base32Hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// BuildNSEC3 returns the NSEC3 chain for the zone at apex (RFC 5155
// §7.1) followed by the NSEC3PARAM for the apex. Each authoritative
// owner name and each empty non-terminal above one gets an NSEC3, owned
// by the base32hex hash of the name under apex and linked in hash
// order, the last back to the first. The bitmap lists the types at the
// name (at a delegation point only NS and DS), RRSIG where the name has
// a signed RRset, and NSEC3PARAM at the apex; an empty non-terminal's
// is empty. With params.OptOut, delegations without DS (and empty
// non-terminals only above them) are left out. Names below a
// delegation (glue) get none, and existing RRSIG / NSEC / NSEC3 /
// NSEC3PARAM records in z are ignored.
//
// ttl 0 uses min(SOA TTL, SOA MINIMUM) (RFC 9077), or 3600 without an
// SOA at the apex; the NSEC3PARAM gets the same TTL. It registers the
// bundled handlers, as [SignZone] does.
func BuildNSEC3(z *zone.Zone, apex string, ttl uint32, params NSEC3Options) ([]*zone.ResourceRecord, error) {
	registerHandlers()
	if len(params.Salt) > maxNSEC3SaltLength {
		return nil, fmt.Errorf("%w: NSEC3 salt of %d octets", ErrSigner, len(params.Salt))
	}
	v, err := newZoneView(z, apex)
	if err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = nsecTTL(z, apex)
	}
	links, err := hashNames(v.nsec3Names(params.OptOut), params)
	if err != nil {
		return nil, err
	}
	salt := "-"
	if len(params.Salt) > 0 {
		salt = strings.ToUpper(hex.EncodeToString(params.Salt))
	}
	flags := 0
	if params.OptOut {
		flags = nsec3FlagOptOut
	}
	out := make([]*zone.ResourceRecord, 0, len(links)+1)
	for i, l := range links {
		next := links[(i+1)%len(links)].hash
		value := strings.TrimSpace(fmt.Sprintf("%d %d %d %s %s %s",
			nsec3HashSHA1, flags, params.Iterations, salt, base32Hex.EncodeToString(next), l.bitmap))
		owner := nsec3Owner(l.hash, apex)
		rr, err := zone.NewResourceRecord(owner, ttl, types.ClassIN, types.TypeNSEC3, value)
		if err != nil {
			return nil, fmt.Errorf("%w: NSEC3 at %s: %v", ErrSigner, owner, err)
		}
		out = append(out, rr)
	}
	param, err := zone.NewResourceRecord(apex, ttl, types.ClassIN, types.TypeNSEC3PARAM,
		fmt.Sprintf("%d 0 %d %s", nsec3HashSHA1, params.Iterations, salt))
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3PARAM: %v", ErrSigner, err)
	}
	return append(out, param), nil
}

// nsec3Link is one name of the chain: its hash and its bitmap text.
type nsec3Link struct {
	hash   []byte
	bitmap string
}

// hashNames hashes every name and returns the links in hash order.
func hashNames(names map[string]string, params NSEC3Options) ([]nsec3Link, error) {
	links := make([]nsec3Link, 0, len(names))
	for name, bitmap := range names {
		h, err := dnssec.ComputeNSEC3Hash(name, nsec3HashSHA1, params.Iterations, params.Salt)
		if err != nil {
			return nil, fmt.Errorf("%w: NSEC3 hash of %s: %v", ErrSigner, name, err)
		}
		links = append(links, nsec3Link{hash: h, bitmap: bitmap})
	}
	slices.SortFunc(links, func(a, b nsec3Link) int { return bytes.Compare(a.hash, b.hash) })
	for i := 1; i < len(links); i++ {
		if bytes.Equal(links[i-1].hash, links[i].hash) {
			return nil, fmt.Errorf("%w: NSEC3 hash collision; use another salt", ErrSigner)
		}
	}
	return links, nil
}

func nsec3Owner(hash []byte, apex string) string {
	label := base32Hex.EncodeToString(hash)
	if apex == "." {
		return label + "."
	}
	return label + "." + apex
}

// nsec3Names returns the lower-cased names that get an NSEC3, each
// with its bitmap text.
func (v *zoneView) nsec3Names(optOut bool) map[string]string {
	names := map[string]string{}
	for _, owner := range v.owners {
		if v.isOccluded(owner) || (optOut && !v.isSigned(owner)) {
			continue
		}
		names[strings.ToLower(owner)] = v.nsec3BitmapText(owner)
		for n := parentName(owner); !sameName(n, v.apex) && isAtOrBelow(n, v.apex); n = parentName(n) {
			if _, isOwner := v.types[n]; !isOwner {
				names[n] = ""
			}
		}
	}
	return names
}

// nsec3BitmapText lists the types for owner's NSEC3 in presentation form.
func (v *zoneView) nsec3BitmapText(owner string) string {
	present := v.chainTypes(owner)
	if v.isSigned(owner) {
		present = append(present, types.TypeRRSIG)
	}
	if sameName(owner, v.apex) {
		present = append(present, types.TypeNSEC3PARAM)
	}
	return typeNames(present)
}

// isSigned reports whether owner has a signed RRset: any authoritative
// name does, a delegation point only with DS.
func (v *zoneView) isSigned(owner string) bool {
	return !v.isCut(owner) || slices.Contains(v.types[strings.ToLower(owner)], types.TypeDS)
}

// parentName returns name one label shorter, lower-cased; the root is
// its own parent.
func parentName(name string) string {
	labels := labelsOf(name)
	if len(labels) <= 1 {
		return "."
	}
	return strings.Join(labels[1:], ".") + "."
}
