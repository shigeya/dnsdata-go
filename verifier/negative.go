package verifier

import (
	"fmt"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// proveNoDS attempts to prove from parent that no DS record exists for
// childName. The proof comes from NSEC or NSEC3 records that the
// resolver previously deposited into parent (RFC 4035 §5.4 for NSEC;
// RFC 5155 §8.9 for NSEC3).
//
// On success the returned reason gives a short human-readable label
// suitable for diagnostic output. On failure (either no proof was
// present or a candidate proof failed signature verification) reason
// explains why.
//
// The function never returns an error: signature verification
// failures cause this individual candidate proof to be skipped, and a
// false return is the safe / conservative outcome ("we can't make any
// Insecure claim, fall back to existing behaviour").
func (v *Verifier) proveNoDS(parent *dnssec.Zone, childName string) (bool, string) {
	if proven, why := v.proveNoDSWithNSEC(parent, childName); proven {
		return true, why
	}
	if proven, why := v.proveNoDSWithNSEC3(parent, childName); proven {
		return true, why
	}
	return false, "no NSEC/NSEC3 records prove no-DS for " + childName
}

// proveNoDSWithNSEC searches parent for a single NSEC RR whose owner
// matches childName AND whose bitmap has the no-DS shape (NS without
// DS or SOA). That NSEC must verify against the parent's keys.
func (v *Verifier) proveNoDSWithNSEC(parent *dnssec.Zone, childName string) (bool, string) {
	candidates := nsecHandlers(parent, childName)
	for _, c := range candidates {
		if !c.nsec.MatchesName(c.owner, childName) {
			continue
		}
		if !c.nsec.ProvesNoDS() {
			continue
		}
		ok, err := parent.VerifyRRSet(c.owner, types.TypeNSEC, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC at %s asserts NS without DS", c.owner)
	}
	return false, ""
}

// proveNoDSWithNSEC3 searches parent for either:
//
//   - A matching NSEC3 whose owner-hash equals H(childName) and whose
//     bitmap has the no-DS shape; or
//   - A covering NSEC3 whose range covers H(childName) AND has the
//     opt-out flag set (RFC 5155 §6).
//
// The first NSEC3PARAM in parent supplies the hash parameters. If no
// NSEC3PARAM is present, every NSEC3 in parent is tried with its own
// (algorithm, iterations, salt).
func (v *Verifier) proveNoDSWithNSEC3(parent *dnssec.Zone, childName string) (bool, string) {
	candidates := nsec3Handlers(parent)
	if len(candidates) == 0 {
		return false, ""
	}

	// Matching denial: owner-hash == hash(childName).
	for _, c := range candidates {
		target, err := dnssec.ComputeNSEC3Hash(childName, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
		if err != nil {
			continue
		}
		if !bytesEqual(target, c.ownerHash) {
			continue
		}
		if !c.h.ProvesNoDS() {
			continue
		}
		ok, err := parent.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC3 at %s (matching hash) asserts NS without DS", c.owner)
	}

	// Covering denial with opt-out.
	for _, c := range candidates {
		if !c.h.HasOptOut() {
			continue
		}
		target, err := dnssec.ComputeNSEC3Hash(childName, c.h.HashAlgorithm, c.h.Iterations, c.h.Salt)
		if err != nil {
			continue
		}
		if !c.h.CoversHash(c.ownerHash, target) {
			continue
		}
		ok, err := parent.VerifyRRSet(c.owner, types.TypeNSEC3, dnssec.KeyModeNone, "")
		if err != nil || !ok {
			continue
		}
		return true, fmt.Sprintf("NSEC3 at %s opt-out covers hash of %s", c.owner, childName)
	}
	return false, ""
}

// nsecCandidate pairs an NSEC handler with its owner name so the
// caller does not have to re-derive Label() from the record list.
type nsecCandidate struct {
	owner string
	nsec  *dnssec.NSEC
}

// nsecHandlers returns every NSEC RR in z. ownerName candidate is
// included so canonical comparison stays a string operation.
func nsecHandlers(z *dnssec.Zone, _ string) []nsecCandidate {
	var out []nsecCandidate
	for _, rr := range z.AllRecords() {
		if rr.Type != types.TypeNSEC {
			continue
		}
		h, ok := rr.Handler().(*dnssec.NSEC)
		if !ok {
			continue
		}
		out = append(out, nsecCandidate{owner: rr.Label, nsec: h})
	}
	return out
}

// nsec3Candidate carries an NSEC3 handler plus its owner name and the
// pre-decoded owner-hash bytes.
type nsec3Candidate struct {
	owner     string
	ownerHash []byte
	h         *dnssec.NSEC3
}

// nsec3Handlers walks z and returns every NSEC3 record with its
// decoded owner-hash. Records whose owner cannot be base32hex-decoded
// are silently skipped (they cannot participate in proofs anyway).
func nsec3Handlers(z *dnssec.Zone) []nsec3Candidate {
	var out []nsec3Candidate
	for _, rr := range z.AllRecords() {
		if rr.Type != types.TypeNSEC3 {
			continue
		}
		h, ok := rr.Handler().(*dnssec.NSEC3)
		if !ok {
			continue
		}
		ownerHash, err := dnssec.OwnerHashFromName(rr.Label)
		if err != nil {
			continue
		}
		out = append(out, nsec3Candidate{owner: rr.Label, ownerHash: ownerHash, h: h})
	}
	return out
}

// bytesEqual is a small helper kept local to avoid pulling bytes.Equal
// into a file that otherwise does not import bytes.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
