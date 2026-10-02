package verifier

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// proveNoData attempts to prove from zone that no rrset of qtype is
// present at qname although the answer is not NXDOMAIN. Three shapes
// are accepted, for both NSEC and NSEC3:
//
//   - qname exists without qtype (RFC 4035 §5.4, RFC 5155 §8.5);
//   - qname is an empty non-terminal (with NSEC: a covering NSEC whose
//     next name is below qname; with NSEC3 the ENT has its own
//     matching record, so the first shape covers it);
//   - wildcard NODATA: qname does not exist, and the wildcard at its
//     closest encloser exists without qtype (RFC 4035 §3.1.3.4,
//     RFC 5155 §8.7).
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
	candidates := nsecHandlers(z, qname)
	if c := findNSEC(z, candidates, func(c nsecCandidate) bool {
		return c.nsec.MatchesName(c.owner, qname) && c.nsec.ProvesNoData(qtype)
	}); c != nil {
		return true, fmt.Sprintf("NSEC at %s asserts qname exists without %s", c.owner, qtypeMnemonic(qtype))
	}

	covering := findNSEC(z, candidates, func(c nsecCandidate) bool {
		return c.nsec.CoversName(c.owner, qname)
	})
	if covering == nil {
		return false, ""
	}
	if isStrictSubdomain(covering.nsec.NextDomain, qname) {
		return true, fmt.Sprintf("NSEC at %s covers empty non-terminal %s (next name %s is below it)",
			covering.owner, qname, covering.nsec.NextDomain)
	}

	ce := closestEncloserNSEC(qname, covering.owner, covering.nsec.NextDomain)
	if ce == "" {
		return false, ""
	}
	wildcard := wildcardAt(ce)
	match := findNSEC(z, candidates, func(c nsecCandidate) bool {
		return c.nsec.MatchesName(c.owner, wildcard) && c.nsec.ProvesNoData(qtype)
	})
	if match == nil {
		return false, ""
	}
	return true, fmt.Sprintf("NSEC at %s covers %s, NSEC at %s asserts wildcard %s exists without %s",
		covering.owner, qname, match.owner, wildcard, qtypeMnemonic(qtype))
}

// proveNXDomainWithNSEC needs a covering NSEC for qname AND a covering
// NSEC for *.<closestEncloser>. The closest encloser is derived from
// the covering NSEC and qname: the longest ancestor of qname that is
// also a suffix of either the NSEC's owner or its NextDomain.
//
// A covering NSEC whose next name is below qname proves qname is an
// empty non-terminal, and an NSEC matching the wildcard proves the
// wildcard exists; neither is NXDOMAIN.
func (v *Verifier) proveNXDomainWithNSEC(z *dnssec.Zone, qname string) (bool, string) {
	candidates := nsecHandlers(z, qname)

	covering := findNSEC(z, candidates, func(c nsecCandidate) bool {
		return c.nsec.CoversName(c.owner, qname)
	})
	if covering == nil || isStrictSubdomain(covering.nsec.NextDomain, qname) {
		return false, ""
	}

	// Both endpoints of the covering NSEC exist in the zone, so any
	// common ancestor with qname is also a name that exists.
	ce := closestEncloserNSEC(qname, covering.owner, covering.nsec.NextDomain)
	if ce == "" || dnssec.EqualCanonicalNames(ce, qname) {
		return false, ""
	}
	wildcard := wildcardAt(ce)

	denial := findNSEC(z, candidates, func(c nsecCandidate) bool {
		return c.nsec.CoversName(c.owner, wildcard)
	})
	if denial == nil {
		return false, ""
	}
	return true, fmt.Sprintf("NSEC at %s covers %s, NSEC at %s denies wildcard %s",
		covering.owner, qname, denial.owner, wildcard)
}

// findNSEC returns the first candidate that satisfies pred and whose
// signature verifies under z's keys, or nil.
func findNSEC(z *dnssec.Zone, candidates []nsecCandidate, pred func(nsecCandidate) bool) *nsecCandidate {
	for i := range candidates {
		c := &candidates[i]
		if !pred(*c) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return c
	}
	return nil
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

	// Wildcard NODATA (RFC 5155 §8.7): closest-encloser proof plus an
	// NSEC3 matching *.<ce> whose bitmap lacks qtype.
	proof, ok := v.closestEncloserProofNSEC3(z, candidates, qname)
	if !ok {
		return false, ""
	}
	wildcard := wildcardAt(proof.ce)
	for _, c := range candidates {
		if !v.nsec3Matches(z, c, wildcard) || !c.h.ProvesNoData(qtype) {
			continue
		}
		return true, fmt.Sprintf("%s; NSEC3 at %s asserts wildcard %s exists without %s",
			proof, c.owner, wildcard, qtypeMnemonic(qtype))
	}
	return false, ""
}

// proveNXDomainWithNSEC3 implements the three-NSEC3 closest-encloser
// proof of RFC 5155 §8.4: closest-encloser match, next-closer cover,
// and wildcard cover.
func (v *Verifier) proveNXDomainWithNSEC3(z *dnssec.Zone, qname string) (bool, string) {
	candidates := nsec3Handlers(z)
	proof, ok := v.closestEncloserProofNSEC3(z, candidates, qname)
	if !ok {
		return false, ""
	}

	// wildcard: "*." + ce. Must be covered by some NSEC3.
	wildcard := wildcardAt(proof.ce)
	wcProven, wcRec := v.findCoveringNSEC3(z, candidates, wildcard)
	if !wcProven {
		return false, ""
	}
	return true, fmt.Sprintf("%s; %s covers wildcard %s", proof, wcRec, wildcard)
}

// nsec3CEProof is a verified RFC 5155 §8.3 closest-encloser proof.
type nsec3CEProof struct {
	ce, ceOwner string // closest encloser and the NSEC3 matching it
	nc, ncOwner string // next closer name and the NSEC3 covering it
}

func (p nsec3CEProof) String() string {
	return fmt.Sprintf("NSEC3 at %s matches closest encloser %s; %s covers next-closer %s",
		p.ceOwner, p.ce, p.ncOwner, p.nc)
}

// closestEncloserProofNSEC3 finds the closest encloser of qname (the
// longest proper ancestor with a matching NSEC3) and an NSEC3 covering
// the next closer name. ok is false when qname itself matches (not a
// non-existence case) or either half of the proof is missing.
func (v *Verifier) closestEncloserProofNSEC3(z *dnssec.Zone, candidates []nsec3Candidate, qname string) (nsec3CEProof, bool) {
	var proof nsec3CEProof
	for _, a := range ancestorsOf(qname) {
		for _, c := range candidates {
			if v.nsec3Matches(z, c, a) {
				proof.ce, proof.ceOwner = a, c.owner
				break
			}
		}
		if proof.ce != "" {
			break
		}
	}
	if proof.ce == "" || dnssec.EqualCanonicalNames(proof.ce, qname) {
		return proof, false
	}
	proof.nc = nextCloserName(qname, proof.ce)
	if proof.nc == "" {
		return proof, false
	}
	covered, owner := v.findCoveringNSEC3(z, candidates, proof.nc)
	if !covered {
		return proof, false
	}
	proof.ncOwner = owner
	return proof, true
}

// nsec3Matches reports whether c's owner hash equals H(name) under c's
// own parameters and c verifies under z's keys.
func (v *Verifier) nsec3Matches(z *dnssec.Zone, c nsec3Candidate, name string) bool {
	h, err := dnssec.ComputeNSEC3Hash(name, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
	if err != nil || !bytesEqual(h, c.ownerHash) {
		return false
	}
	ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
	return err == nil && ok
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

// wildcardAt returns the wildcard name directly below ce.
func wildcardAt(ce string) string {
	if ce == "." {
		return "*."
	}
	return "*." + ce
}

// isStrictSubdomain reports whether name is below (not equal to)
// parent.
func isStrictSubdomain(name, parent string) bool {
	nl := canonLabelsTrim(name)
	pl := canonLabelsTrim(parent)
	if len(nl) <= len(pl) {
		return false
	}
	return dnssec.EqualCanonicalNames(longestCommonAncestor(name, parent), parent)
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
