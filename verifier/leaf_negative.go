package verifier

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// proveNoData attempts to prove from zone that qname exists but no
// rrset of qtype is present (RFC 4035 §5.4 NSEC NODATA, RFC 5155 §8.5
// NSEC3 NODATA).
//
// On success the returned reason names the NSEC / NSEC3 record(s) that
// produced the proof. Like [Verifier.proveNoDS], every candidate must
// be signature-verified against the zone's keys; a candidate whose
// signature does not verify is silently skipped, never reported as an
// error.
func (v *Verifier) proveNoData(z *dnssec.Zone, qname string, qtype uint16) (bool, string) {
	if proven, why := v.proveNoDataWithNSEC(z, qname, qtype); proven {
		return true, why
	}
	if proven, why := v.proveNoDataWithNSEC3(z, qname, qtype); proven {
		return true, why
	}
	return false, ""
}

// proveNXDomain attempts to prove qname has no records of any type
// (NXDOMAIN). The proof shape requires *two* pieces of evidence:
//
//   - That qname itself has no exact match (an NSEC/NSEC3 covering it).
//   - That no wildcard *.<closest-encloser> exists which could have
//     synthesised an answer for qname (a separate NSEC/NSEC3 either
//     covering the wildcard name or matching it with a bitmap that
//     excludes qtype).
//
// Without the wildcard proof, an attacker controlling a zone with a
// wildcard could lie about NXDOMAIN by suppressing the wildcard
// answer.
func (v *Verifier) proveNXDomain(z *dnssec.Zone, qname string) (bool, string) {
	if proven, why := v.proveNXDomainWithNSEC(z, qname); proven {
		return true, why
	}
	if proven, why := v.proveNXDomainWithNSEC3(z, qname); proven {
		return true, why
	}
	return false, ""
}

// --- NSEC ---------------------------------------------------------------

func (v *Verifier) proveNoDataWithNSEC(z *dnssec.Zone, qname string, qtype uint16) (bool, string) {
	for _, c := range nsecHandlers(z, qname) {
		if !c.nsec.MatchesName(c.owner, qname) {
			continue
		}
		if !c.nsec.ProvesNoData(qtype) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC at %s asserts qname exists without %s", c.owner, qtypeMnemonic(qtype))
	}
	return false, ""
}

// proveNXDomainWithNSEC needs a covering NSEC for qname AND a covering
// (or matching with appropriate bitmap) NSEC for *.<closestEncloser>.
// The closest encloser is derived from the covering NSEC and qname:
// the longest ancestor of qname that is also a suffix of either the
// NSEC's owner or its NextDomain.
func (v *Verifier) proveNXDomainWithNSEC(z *dnssec.Zone, qname string) (bool, string) {
	candidates := nsecHandlers(z, qname)

	// 1. Find any NSEC that covers qname.
	var covering *nsecCandidate
	for i := range candidates {
		c := &candidates[i]
		if !c.nsec.CoversName(c.owner, qname) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		covering = c
		break
	}
	if covering == nil {
		return false, ""
	}

	// 2. Compute the closest encloser candidate: longest ancestor of
	//    qname that is also an ancestor of the covering NSEC's owner
	//    or NextDomain. Both endpoints exist in the zone so any
	//    common ancestor with qname is also a name that exists.
	ce := closestEncloserNSEC(qname, covering.owner, covering.nsec.NextDomain)
	if ce == "" {
		return false, ""
	}
	wildcard := "*." + ce

	// 3. Find an NSEC that either covers *.<ce> (wildcard doesn't
	//    exist) or matches it with a bitmap proving NODATA for any
	//    qtype — but since qname is NXDOMAIN we only care that the
	//    wildcard itself doesn't exist as an answer name.
	for _, c := range candidates {
		if c.nsec.CoversName(c.owner, wildcard) || c.nsec.MatchesName(c.owner, wildcard) {
			ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC, dnssec.KeyModeNone, "")
			if err != nil || !ok {
				continue
			}
			return true, fmt.Sprintf("NSEC at %s covers %s, NSEC at %s denies wildcard %s",
				covering.owner, qname, c.owner, wildcard)
		}
	}
	return false, ""
}

// closestEncloserNSEC returns the longest name that is a suffix of
// qname AND a suffix of at least one of {owner, next}. Returns "" if
// no common ancestor exists (qname disjoint from the NSEC's range
// owners, which would itself indicate the response is inconsistent).
func closestEncloserNSEC(qname, owner, next string) string {
	cands := []string{owner, next}
	best := ""
	for _, c := range cands {
		anc := longestCommonAncestor(qname, c)
		if labelCount(anc) > labelCount(best) {
			best = anc
		}
	}
	return best
}

// --- NSEC3 --------------------------------------------------------------

func (v *Verifier) proveNoDataWithNSEC3(z *dnssec.Zone, qname string, qtype uint16) (bool, string) {
	candidates := nsec3Handlers(z)
	for _, c := range candidates {
		target, err := dnssec.ComputeNSEC3Hash(qname, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
		if err != nil {
			continue
		}
		if !bytesEqual(target, c.ownerHash) {
			continue
		}
		if !c.h.ProvesNoData(qtype) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC3 at %s asserts qname exists without %s", c.owner, qtypeMnemonic(qtype))
	}
	return false, ""
}

// proveNXDomainWithNSEC3 implements the three-NSEC3 closest-encloser
// proof of RFC 5155 §8.4: closest-encloser match, next-closer cover,
// and wildcard cover.
func (v *Verifier) proveNXDomainWithNSEC3(z *dnssec.Zone, qname string) (bool, string) {
	candidates := nsec3Handlers(z)
	if len(candidates) == 0 {
		return false, ""
	}

	// Walk ancestors of qname from longest to shortest. The first
	// ancestor whose hash matches some NSEC3's owner-hash is the
	// closest encloser.
	ancestors := ancestorsOf(qname)
	var ce string
	var ceCandidate *nsec3Candidate
	for _, a := range ancestors {
		for i := range candidates {
			c := &candidates[i]
			target, err := dnssec.ComputeNSEC3Hash(a, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
			if err != nil {
				continue
			}
			if !bytesEqual(target, c.ownerHash) {
				continue
			}
			ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
			if err != nil || !ok {
				continue
			}
			ce = a
			ceCandidate = c
			break
		}
		if ce != "" {
			break
		}
	}
	if ce == "" || ce == qname {
		// qname itself matches → not an NXDOMAIN case (would be
		// NODATA), or no ancestor matched.
		return false, ""
	}

	// next-closer name: ce with one more label from qname prepended.
	nc := nextCloserName(qname, ce)
	if nc == "" {
		return false, ""
	}
	ncProven, ncRec := v.findCoveringNSEC3(z, candidates, nc)
	if !ncProven {
		return false, ""
	}

	// wildcard: "*." + ce. Must be covered by some NSEC3.
	wildcard := "*." + ce
	wcProven, wcRec := v.findCoveringNSEC3(z, candidates, wildcard)
	if !wcProven {
		return false, ""
	}

	return true, fmt.Sprintf("NSEC3 at %s matches closest encloser %s; %s covers next-closer %s; %s covers wildcard %s",
		ceCandidate.owner, ce, ncRec, nc, wcRec, wildcard)
}

// findCoveringNSEC3 returns (true, ownerName) if any NSEC3 in cands
// has a range covering H(target) and verifies under z's keys.
func (v *Verifier) findCoveringNSEC3(z *dnssec.Zone, cands []nsec3Candidate, target string) (bool, string) {
	for _, c := range cands {
		h, err := dnssec.ComputeNSEC3Hash(target, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
		if err != nil {
			continue
		}
		if !c.h.CoversHash(c.ownerHash, h) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, c.owner
	}
	return false, ""
}

// --- name helpers -------------------------------------------------------

// ancestorsOf returns qname's ancestors in canonical descending order:
// longest (qname itself) first, root last. Each entry carries the
// trailing dot.
func ancestorsOf(qname string) []string {
	qname = strings.ToLower(strings.TrimSpace(qname))
	if qname == "" || qname == "." {
		return []string{"."}
	}
	trimmed := strings.TrimSuffix(qname, ".")
	labels := strings.Split(trimmed, ".")
	out := make([]string, 0, len(labels)+1)
	for i := 0; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], ".")+".")
	}
	out = append(out, ".")
	return out
}

// nextCloserName returns the ancestor of qname that is one label
// longer than ce. Returns "" if ce is not actually an ancestor of
// qname or if ce already equals qname.
func nextCloserName(qname, ce string) string {
	ancs := ancestorsOf(qname)
	for i, a := range ancs {
		if dnssec.EqualCanonicalNames(a, ce) {
			if i == 0 {
				return ""
			}
			return ancs[i-1]
		}
	}
	return ""
}

// longestCommonAncestor returns the longest name that is a suffix of
// both a and b in canonical form. The empty root "." is the lower
// bound and is returned when no labels match.
func longestCommonAncestor(a, b string) string {
	la := canonLabelsTrim(a)
	lb := canonLabelsTrim(b)
	matched := 0
	for i := 0; i < len(la) && i < len(lb); i++ {
		ai := la[len(la)-1-i]
		bi := lb[len(lb)-1-i]
		if !strings.EqualFold(ai, bi) {
			break
		}
		matched++
	}
	if matched == 0 {
		return "."
	}
	common := la[len(la)-matched:]
	return strings.Join(common, ".") + "."
}

// canonLabelsTrim splits name into lower-case labels left-to-right,
// stripping any trailing dot.
func canonLabelsTrim(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// labelCount returns the number of labels in name (root "." is 0).
func labelCount(name string) int {
	return len(canonLabelsTrim(name))
}
