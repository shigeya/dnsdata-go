package memory

import (
	"bytes"
	"fmt"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// nsec3Entry is an NSEC3 record at owner, with the hash its owner
// label carries.
type nsec3Entry struct {
	owner string
	hash  []byte
	nsec3 *dnssec.NSEC3
}

// nsec3Chain is a zone's NSEC3 records. Names are hashed with the
// parameters of the first record; a signer uses one set per chain.
type nsec3Chain struct {
	entries []nsec3Entry
}

func (c *nsec3Chain) add(owner, value string) error {
	n, err := dnssec.ParseNSEC3(nil, value)
	if err != nil {
		return fmt.Errorf("%w: NSEC3 at %s: %v", ErrConfig, owner, err)
	}
	h, err := dnssec.OwnerHashFromName(owner)
	if err != nil {
		return fmt.Errorf("%w: NSEC3 owner %s: %v", ErrConfig, owner, err)
	}
	c.entries = append(c.entries, nsec3Entry{owner: owner, hash: h, nsec3: n})
	return nil
}

// hash returns name's NSEC3 hash, or nil when it cannot be computed.
func (c *nsec3Chain) hash(name string) []byte {
	first := c.entries[0].nsec3
	h, err := dnssec.ComputeNSEC3Hash(name, first.HashAlgorithm, first.Iterations, first.Salt)
	if err != nil {
		return nil
	}
	return h
}

// matching returns the owner of the NSEC3 whose hash is name's, or "".
func (c *nsec3Chain) matching(name string) string {
	h := c.hash(name)
	for _, e := range c.entries {
		if h != nil && bytes.Equal(e.hash, h) {
			return e.owner
		}
	}
	return ""
}

// covering returns the owner of the NSEC3 whose range covers name's
// hash, or "".
func (c *nsec3Chain) covering(name string) string {
	h := c.hash(name)
	for _, e := range c.entries {
		if h != nil && e.nsec3.CoversHash(e.hash, h) {
			return e.owner
		}
	}
	return ""
}

// nsec3At returns the NSEC3 at owner with its signatures; nil for "".
func (idx *zoneIndex) nsec3At(owner string) []*zone.ResourceRecord {
	if owner == "" {
		return nil
	}
	return idx.withSigs(owner, types.TypeNSEC3)
}

// closestEncloserProof is the closest provable encloser proof of RFC
// 5155 §7.2.1: the NSEC3 matching the nearest ancestor of name that has
// one, and the NSEC3 covering the next closer name. It also returns
// that ancestor.
func (idx *zoneIndex) closestEncloserProof(name string) ([]*zone.ResourceRecord, string) {
	for ce := parent(name); isAtOrBelow(ce, idx.apex); ce = parent(ce) {
		if owner := idx.nsec3.matching(ce); owner != "" {
			proof := append(idx.nsec3At(owner), idx.nsec3At(idx.nsec3.covering(nextCloser(name, ce)))...)
			return proof, ce
		}
		if ce == idx.apex {
			break
		}
	}
	return nil, idx.apex
}
