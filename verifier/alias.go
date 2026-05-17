package verifier

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
)

// tryCNAME looks for a CNAME rrset at qname inside currentZone, verifies
// its signature against currentZone's keys, and packages it as an
// [AliasStep] hop for the outer Validate loop to chase.
//
// Returns (nil, nil, nil) when no CNAME is present — the caller then
// continues with DNAME or negative-proof handling. A CNAME present but
// failing signature verification returns a hop whose Verdict is Bogus
// (and the alias still points at the target, so chasing can stop or
// continue per the worst-of policy).
func (v *Verifier) tryCNAME(currentZone *dnssec.Zone, currentName, qname string) (*AliasStep, *hopOutcome, error) {
	rrset := currentZone.FindRRSet(qname, types.TypeCNAME)
	if len(rrset) == 0 {
		return nil, nil, nil
	}

	target := strings.TrimSpace(rrset[0].Value)
	target = normalizeQName(target)
	if target == "" {
		return nil, &hopOutcome{
			Verdict:     VerdictBogus,
			BogusAt:     qname,
			BogusReason: "CNAME target is empty",
		}, nil
	}

	ok, err := currentZone.VerifyRRSet(qname, types.TypeCNAME, dnssec.KeyModeNone, "")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrVerifier, err)
	}
	if !ok {
		return nil, &hopOutcome{
			Verdict:     VerdictBogus,
			BogusAt:     currentName,
			BogusReason: fmt.Sprintf("RRSIG over %s/CNAME did not verify", qname),
		}, nil
	}

	alias := &AliasStep{
		Type:   "cname",
		From:   qname,
		Target: target,
		Zone:   currentName,
	}
	return alias, &hopOutcome{Verdict: VerdictSecure, Alias: alias}, nil
}

// tryDNAME looks for a DNAME at any proper ancestor of qname inside
// currentZone. RFC 6672 §3 specifies that a DNAME at OWNER rewrites
// every name BELOW (not equal to) owner under the DNAME's target.
//
// Implementation: walk qname's ancestors from longest to shortest;
// the first one carrying a DNAME wins. The synthesised qname is
// strict suffix replacement of OWNER with TARGET.
func (v *Verifier) tryDNAME(currentZone *dnssec.Zone, currentName, qname string) (*AliasStep, *hopOutcome, error) {
	ancestors := ancestorsOf(qname)
	for _, anc := range ancestors {
		if dnssec.EqualCanonicalNames(anc, qname) {
			// DNAME at qname itself does not synthesise (RFC 6672 §3.1).
			continue
		}
		rrset := currentZone.FindRRSet(anc, types.TypeDNAME)
		if len(rrset) == 0 {
			continue
		}
		target := strings.TrimSpace(rrset[0].Value)
		target = normalizeQName(target)
		if target == "" {
			return nil, &hopOutcome{
				Verdict:     VerdictBogus,
				BogusAt:     anc,
				BogusReason: "DNAME target is empty",
			}, nil
		}

		ok, err := currentZone.VerifyRRSet(anc, types.TypeDNAME, dnssec.KeyModeNone, "")
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrVerifier, err)
		}
		if !ok {
			return nil, &hopOutcome{
				Verdict:     VerdictBogus,
				BogusAt:     currentName,
				BogusReason: fmt.Sprintf("RRSIG over %s/DNAME did not verify", anc),
			}, nil
		}

		synth := synthesiseDNAMETarget(qname, anc, target)
		if synth == "" {
			return nil, &hopOutcome{
				Verdict:     VerdictBogus,
				BogusAt:     anc,
				BogusReason: fmt.Sprintf("DNAME at %s could not synthesise target for %s", anc, qname),
			}, nil
		}
		alias := &AliasStep{
			Type:   "dname",
			From:   qname,
			Target: synth,
			Zone:   currentName,
		}
		return alias, &hopOutcome{Verdict: VerdictSecure, Alias: alias}, nil
	}
	return nil, nil, nil
}

// synthesiseDNAMETarget rewrites qname per RFC 6672 §5.3.1: the
// labels under owner are appended to the DNAME target.
//
// Example:
//
//	qname = "foo.bar.example.com.", owner = "example.com.",
//	target = "elsewhere.net." → "foo.bar.elsewhere.net."
func synthesiseDNAMETarget(qname, owner, target string) string {
	qLabels := canonLabelsTrim(qname)
	oLabels := canonLabelsTrim(owner)
	tLabels := canonLabelsTrim(target)
	if len(qLabels) <= len(oLabels) {
		return ""
	}
	// qname must end with owner.
	for i := 0; i < len(oLabels); i++ {
		ql := qLabels[len(qLabels)-len(oLabels)+i]
		ol := oLabels[i]
		if !strings.EqualFold(ql, ol) {
			return ""
		}
	}
	prefix := qLabels[:len(qLabels)-len(oLabels)]
	all := append(append([]string(nil), prefix...), tLabels...)
	return strings.Join(all, ".") + "."
}
