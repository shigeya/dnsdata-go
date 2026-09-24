package memory

import (
	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

const (
	rcodeNoError  = uint8(types.RCodeNoError)
	rcodeNXDomain = uint8(types.RCodeNXDomain)
	rcodeRefused  = uint8(types.RCodeRefused)
)

// answer builds the response of one zone to (name, qtype); name is
// normalized and at or below the apex.
func (idx *zoneIndex) answer(name string, qtype uint16) resolver.Response {
	if cut := idx.cutAbove(name); cut != "" && !(qtype == types.TypeDS && name == cut) {
		return idx.referral(cut)
	}
	if len(idx.byName[name]) > 0 {
		return idx.existing(name, qtype)
	}
	if idx.exists[name] {
		// Empty non-terminal: NODATA, proven by the NSEC spanning it.
		return response(rcodeNoError, idx.coveringNSEC(name))
	}
	if owner := idx.dnameAbove(name); owner != "" {
		return response(rcodeNoError, idx.withSigs(owner, types.TypeDNAME))
	}
	return idx.missing(name, qtype)
}

// referral answers a name at or below a delegation point: the NS
// RRset, and the signed DS RRset or the NSEC proving there is none.
func (idx *zoneIndex) referral(cut string) resolver.Response {
	records := idx.rrset(cut, types.TypeNS)
	if ds := idx.withSigs(cut, types.TypeDS); len(ds) > 0 {
		records = append(records, ds...)
	} else {
		records = append(records, idx.withSigs(cut, types.TypeNSEC)...)
	}
	return response(rcodeNoError, records)
}

// existing answers a name that owns records: the RRset, a CNAME to
// follow, or NODATA with the name's NSEC.
func (idx *zoneIndex) existing(name string, qtype uint16) resolver.Response {
	if rs := idx.withSigs(name, qtype); len(rs) > 0 {
		return response(rcodeNoError, rs)
	}
	if qtype != types.TypeCNAME {
		if cname := idx.withSigs(name, types.TypeCNAME); len(cname) > 0 {
			return response(rcodeNoError, cname)
		}
	}
	return response(rcodeNoError, idx.withSigs(name, types.TypeNSEC))
}

// missing answers a name that does not exist: wildcard synthesis when
// `*.<closest encloser>` exists (RFC 4035 §3.1.3.3), NXDOMAIN otherwise.
func (idx *zoneIndex) missing(name string, qtype uint16) resolver.Response {
	ce := idx.closestEncloser(name)
	wildcard := wildcardOf(ce)
	if len(idx.byName[wildcard]) == 0 {
		records := append(idx.coveringNSEC(name), idx.coveringNSEC(wildcard)...)
		return response(rcodeNXDomain, records)
	}
	proof := idx.coveringNSEC(nextCloser(name, ce))
	rs := idx.withSigs(wildcard, qtype)
	if len(rs) == 0 {
		return response(rcodeNoError, append(proof, idx.withSigs(wildcard, types.TypeNSEC)...))
	}
	synthesised := make([]*zone.ResourceRecord, 0, len(rs)+len(proof))
	for _, rr := range rs {
		synthesised = append(synthesised, copyAs(rr, name))
	}
	return response(rcodeNoError, append(synthesised, proof...))
}

// response copies records (so callers cannot alter the authority and
// concurrent queries share nothing mutable) and drops duplicates.
func response(rcode uint8, records []*zone.ResourceRecord) resolver.Response {
	type key struct {
		label, value string
		rrtype       uint16
	}
	seen := map[key]bool{}
	out := make([]*zone.ResourceRecord, 0, len(records))
	for _, rr := range records {
		k := key{rr.Label, rr.Value, rr.Type}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, copyAs(rr, rr.Label))
	}
	return resolver.Response{Records: out, RCode: rcode}
}

// copyAs returns a fresh copy of rr with the given owner.
func copyAs(rr *zone.ResourceRecord, owner string) *zone.ResourceRecord {
	return &zone.ResourceRecord{Label: owner, TTL: rr.TTL, Class: rr.Class, Type: rr.Type, Value: rr.Value}
}
