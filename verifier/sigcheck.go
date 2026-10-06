package verifier

import (
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
)

// SigCheck.Result values. They are the String forms of
// [dnssec.SigStatus].
const (
	SigVerified             = "verified"
	SigExpired              = "expired"
	SigNotYetValid          = "not-yet-valid"
	SigUnsupportedAlgorithm = "unsupported-algorithm"
	SigNoMatchingKey        = "no-matching-key"
	SigInvalid              = "invalid"
)

// sigChecks turns the per-RRSIG results over (name, rrtype) into
// SigChecks.
func sigChecks(name string, results []dnssec.SigResult) []SigCheck {
	out := make([]SigCheck, 0, len(results))
	for _, r := range results {
		out = append(out, SigCheck{
			Name:       name,
			RRType:     r.RRSig.TypeCovered,
			KeyTag:     r.RRSig.KeyTag,
			Algorithm:  r.RRSig.Algorithm,
			Signer:     r.RRSig.Signer,
			Inception:  time.Unix(r.RRSig.Inception, 0).UTC(),
			Expiration: time.Unix(r.RRSig.Expire, 0).UTC(),
			Result:     r.Status.String(),
		})
	}
	return out
}

// addStep puts step into result.Chain. A step for the same zone added
// by an earlier hop is kept, and only the signature checks it lacks are
// appended to it, so re-walking a zone adds nothing twice.
func (v *Verifier) addStep(result *Result, step ZoneStep) {
	for i := range result.Chain {
		if result.Chain[i].Zone == step.Zone {
			v.addSigs(result, i, step.Signatures)
			return
		}
	}
	checks := step.Signatures
	step.Signatures = nil
	result.Chain = append(result.Chain, step)
	v.emit(StepZone, step.Zone, "")
	v.addSigs(result, len(result.Chain)-1, checks)
}

// addZoneSigs appends checks to the chain step of zoneName, which the
// walk has already added.
func (v *Verifier) addZoneSigs(result *Result, zoneName string, checks []SigCheck) {
	v.addStep(result, ZoneStep{Zone: zoneName, Signatures: checks})
}

// addSigs appends to result.Chain[i] each check it does not hold yet,
// reporting each one as a [StepSig] event.
func (v *Verifier) addSigs(result *Result, i int, checks []SigCheck) {
	step := &result.Chain[i]
	for _, c := range checks {
		if containsSig(step.Signatures, c) {
			continue
		}
		step.Signatures = append(step.Signatures, c)
		v.emitSig(step.Zone, c)
	}
}

func containsSig(list []SigCheck, c SigCheck) bool {
	for _, s := range list {
		if s.Name == c.Name && s.RRType == c.RRType && s.KeyTag == c.KeyTag &&
			s.Algorithm == c.Algorithm && s.Signer == c.Signer && s.Result == c.Result &&
			s.Inception.Equal(c.Inception) && s.Expiration.Equal(c.Expiration) {
			return true
		}
	}
	return false
}
