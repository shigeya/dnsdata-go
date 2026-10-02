package memory

import (
	"strings"

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
		// Empty non-terminal: NODATA.
		return response(rcodeNoError, idx.noDataProof(name))
	}
	if owner := idx.dnameAbove(name); owner != "" {
		return idx.dnameAnswer(name, owner)
	}
	return idx.missing(name, qtype)
}

// dnameAnswer answers a name below the DNAME at owner: the signed DNAME
// and the CNAME synthesised from it (RFC 6672 §5.3.1), owned by name,
// unsigned, with the DNAME's TTL.
func (idx *zoneIndex) dnameAnswer(name, owner string) resolver.Response {
	dname := idx.withSigs(owner, types.TypeDNAME)
	target := normalize(idx.rrset(owner, types.TypeDNAME)[0].Value)
	prefix := labels(name)[:len(labels(name))-len(labels(owner))]
	synthesised := &zone.ResourceRecord{
		Label: name,
		TTL:   dname[0].TTL,
		Class: dname[0].Class,
		Type:  types.TypeCNAME,
		Value: strings.Join(append(prefix, labels(target)...), ".") + ".",
	}
	return response(rcodeNoError, append(dname, synthesised))
}

// referral answers a name at or below a delegation point: the NS
// RRset, and the signed DS RRset or the proof there is none.
func (idx *zoneIndex) referral(cut string) resolver.Response {
	records := idx.rrset(cut, types.TypeNS)
	if ds := idx.withSigs(cut, types.TypeDS); len(ds) > 0 {
		records = append(records, ds...)
	} else {
		records = append(records, idx.noDataProof(cut)...)
	}
	return response(rcodeNoError, records)
}

// existing answers a name that owns records: the RRset, a CNAME to
// follow, or NODATA.
func (idx *zoneIndex) existing(name string, qtype uint16) resolver.Response {
	if rs := idx.withSigs(name, qtype); len(rs) > 0 {
		return response(rcodeNoError, rs)
	}
	if qtype != types.TypeCNAME {
		if cname := idx.withSigs(name, types.TypeCNAME); len(cname) > 0 {
			return response(rcodeNoError, cname)
		}
	}
	return response(rcodeNoError, idx.noDataProof(name))
}

// missing answers a name that does not exist: wildcard synthesis when
// `*.<closest encloser>` exists (RFC 4035 §3.1.3.3), NXDOMAIN otherwise.
// A wildcard CNAME is synthesised for a query of any type
// (RFC 4592 §3.3.3).
func (idx *zoneIndex) missing(name string, qtype uint16) resolver.Response {
	ce := idx.closestEncloser(name)
	wildcard := wildcardOf(ce)
	if len(idx.byName[wildcard]) == 0 {
		return response(rcodeNXDomain, idx.nxDomainProof(name, ce))
	}
	proof := idx.nextCloserProof(name, ce)
	rs := idx.withSigs(wildcard, qtype)
	if len(rs) == 0 && qtype != types.TypeCNAME {
		rs = idx.withSigs(wildcard, types.TypeCNAME)
	}
	if len(rs) == 0 {
		// Wildcard NODATA (RFC 5155 §7.2.5 for NSEC3).
		proof = append(idx.encloserProof(ce), proof...)
		return response(rcodeNoError, append(proof, idx.noDataProof(wildcard)...))
	}
	synthesised := make([]*zone.ResourceRecord, 0, len(rs)+len(proof))
	for _, rr := range rs {
		synthesised = append(synthesised, copyAs(rr, name))
	}
	return response(rcodeNoError, append(synthesised, proof...))
}

// noDataProof proves that name has no RRset of the asked type: the
// NSEC at name, or for an empty non-terminal the NSEC covering it; the
// NSEC3 matching name (RFC 5155 §7.2.3), or without one (opt-out) the
// closest provable encloser proof (§7.2.4).
func (idx *zoneIndex) noDataProof(name string) []*zone.ResourceRecord {
	if idx.nsec3 == nil {
		if nsec := idx.withSigs(name, types.TypeNSEC); len(nsec) > 0 {
			return nsec
		}
		return idx.coveringNSEC(name)
	}
	if owner := idx.nsec3.matching(name); owner != "" {
		return idx.nsec3At(owner)
	}
	proof, _ := idx.closestEncloserProof(name)
	return proof
}

// nxDomainProof proves that name does not exist and that no wildcard
// at its closest encloser ce does: NSECs covering both, or the closest
// encloser proof and the NSEC3 covering the wildcard (RFC 5155 §7.2.2).
func (idx *zoneIndex) nxDomainProof(name, ce string) []*zone.ResourceRecord {
	if idx.nsec3 == nil {
		return append(idx.coveringNSEC(name), idx.coveringNSEC(wildcardOf(ce))...)
	}
	proof, provable := idx.closestEncloserProof(name)
	return append(proof, idx.nsec3At(idx.nsec3.covering(wildcardOf(provable)))...)
}

// nextCloserProof proves that the next closer name of name below its
// closest encloser ce does not exist, as a wildcard answer needs
// (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
func (idx *zoneIndex) nextCloserProof(name, ce string) []*zone.ResourceRecord {
	if idx.nsec3 == nil {
		return idx.coveringNSEC(nextCloser(name, ce))
	}
	return idx.nsec3At(idx.nsec3.covering(nextCloser(name, ce)))
}

// encloserProof is the NSEC3 matching the closest encloser ce, which
// NSEC3 wildcard NODATA adds (RFC 5155 §7.2.5); NSEC needs none.
func (idx *zoneIndex) encloserProof(ce string) []*zone.ResourceRecord {
	if idx.nsec3 == nil {
		return nil
	}
	return idx.nsec3At(idx.nsec3.matching(ce))
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
