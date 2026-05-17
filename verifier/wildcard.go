package verifier

import (
	"fmt"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// detectWildcard reports whether the (qname, qtype) rrset in z was
// produced by wildcard expansion, by comparing the covering RRSIG's
// Labels field with qname's label count (RFC 4034 §3.1.3,
// RFC 4035 §5.3.2).
//
// Returns nil when no synthesis is detectable. Returns a populated
// [WildcardInfo] (still without ProofReason) when synthesis is
// observed; the caller is expected to verify non-existence of the
// next-closer name before promoting it to Result.
func detectWildcard(z *dnssec.Zone, qname string, qtype uint16) *WildcardInfo {
	sigs := z.FindRRSIGs(qname, qtype, "")
	if len(sigs) == 0 {
		return nil
	}
	qLabels := dnssec.LabelCount(qname)
	for _, sig := range sigs {
		if int(sig.Labels) >= qLabels {
			continue
		}
		closest := dnssec.LastNLabels(qname, int(sig.Labels))
		nextCloser := dnssec.LastNLabels(qname, int(sig.Labels)+1)
		return &WildcardInfo{
			Source:          "*." + closest,
			ClosestEncloser: closest,
			NextCloser:      nextCloser,
		}
	}
	return nil
}

// proveQnameNonExistence proves that nextCloser does not exist as a
// signed name in z. RFC 4035 §5.3.4 requires this proof to accompany
// any wildcard-synthesised positive answer; without it an attacker
// could replay the wildcard rrset for a name that actually has its
// own rrset.
//
// Two proof shapes are accepted:
//
//   - An NSEC whose range covers nextCloser, signed under z's keys.
//   - An NSEC3 whose range covers H(nextCloser), signed under z's keys.
//
// Returns (true, reason) on success, (false, "") otherwise.
func (v *Verifier) proveQnameNonExistence(z *dnssec.Zone, nextCloser string) (bool, string) {
	// NSEC first.
	for _, c := range nsecHandlers(z, nextCloser) {
		if !c.nsec.CoversName(c.owner, nextCloser) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC at %s covers next-closer %s", c.owner, nextCloser)
	}
	// NSEC3.
	candidates := nsec3Handlers(z)
	for _, c := range candidates {
		target, err := dnssec.ComputeNSEC3Hash(nextCloser, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
		if err != nil {
			continue
		}
		if !c.h.CoversHash(c.ownerHash, target) {
			continue
		}
		ok, err := z.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC3 at %s covers hash of next-closer %s", c.owner, nextCloser)
	}
	return false, ""
}
