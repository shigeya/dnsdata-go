package verifier

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// Validate walks the DNSSEC chain of trust from the root zone down to
// (qname, qtype), classifies the outcome, and returns the evidence
// gathered along the way.
//
// See DESIGN.md §3 for the contract. Errors returned from Validate
// represent failures that prevented the verifier from forming any
// opinion (typically wrapping [ErrResolver], [ErrChainTimeout], or
// [ErrInvalidQName]); a returned Result is non-nil whenever the
// classification itself ran to completion, even when the verdict is
// Bogus or Insecure.
func (v *Verifier) Validate(ctx context.Context, qname string, qtype uint16) (*Result, error) {
	if qname == "" {
		return nil, fmt.Errorf("%w: qname is empty", ErrInvalidQName)
	}
	qname = normalizeQName(qname)

	result := &Result{
		Verdict:  VerdictIndeterminate,
		Evidence: Evidence{DNSKEYs: map[string][]string{}, DSes: map[string][]string{}, RRSIGs: map[string][]string{}},
	}

	if err := ctx.Err(); err != nil {
		return result, joinChainErr(err)
	}

	// Step 1: load and validate the root zone.
	rootZone, rootKSK, err := v.validateRoot(ctx, result)
	if err != nil {
		return result, err
	}
	if rootZone == nil {
		// validateRoot set result.Verdict to Bogus.
		return result, nil
	}
	result.Chain = append(result.Chain, summarizeZone(".", rootZone, rootKSK))

	// Step 2: descend through each label boundary that's actually a
	// zone cut (= has DS records in the parent).
	currentZone := rootZone
	currentName := "."
	for _, childName := range descendantZones(qname) {
		if err := ctx.Err(); err != nil {
			return result, joinChainErr(err)
		}
		childZone, childKSK, status, err := v.descendInto(ctx, currentZone, currentName, childName, result)
		if err != nil {
			return result, err
		}
		switch status {
		case descendDescended:
			result.Chain = append(result.Chain, summarizeZone(childName, childZone, childKSK))
			currentZone = childZone
			currentName = childName
		case descendInsecure:
			result.InsecureAt = childName
			result.Verdict = VerdictInsecure
			return result, nil
		case descendBogus:
			result.Verdict = VerdictBogus
			result.BogusAt = childName
			if result.BogusReason == "" {
				result.BogusReason = "DS or DNSKEY verification failed"
			}
			return result, nil
		case descendNoCut:
			// child label is not a zone cut — stop descending and
			// query qname inside the current zone.
			goto leaf
		}
	}

leaf:
	if err := ctx.Err(); err != nil {
		return result, joinChainErr(err)
	}

	// Step 3: load the qname/qtype rrset into the deepest validated
	// zone and verify its signature.
	added, err := v.loadRecords(ctx, currentZone, qname, qtype, result)
	if err != nil {
		return result, err
	}
	if added == 0 {
		// NODATA / NXDOMAIN at the leaf. Try NSEC / NSEC3 proofs in
		// the same response: a matching NSEC/NSEC3 with the qtype
		// missing from its bitmap is NODATA; a covering NSEC/NSEC3
		// plus a wildcard-non-existence proof is NXDOMAIN. Without a
		// proof we still report Indeterminate (the response is
		// inconclusive — perhaps the resolver stripped the authority
		// section).
		if proven, reason := v.proveNoData(currentZone, qname, qtype); proven {
			result.Verdict = VerdictSecureNoData
			result.NegativeReason = reason
			return result, nil
		}
		if proven, reason := v.proveNXDomain(currentZone, qname); proven {
			result.Verdict = VerdictSecureNXDomain
			result.NegativeReason = reason
			return result, nil
		}
		return result, nil
	}
	ok, err := currentZone.VerifyRRSet(qname, qtype, dnssec.KeyModeNone, "")
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrVerifier, err)
	}
	if !ok {
		result.Verdict = VerdictBogus
		result.BogusAt = currentName
		result.BogusReason = fmt.Sprintf("RRSIG over %s/%s did not verify", qname, qtypeMnemonic(qtype))
		return result, nil
	}
	result.Verdict = VerdictSecure
	return result, nil
}

// descendStatus is the four-way outcome of a single descent step.
type descendStatus uint8

const (
	descendDescended descendStatus = iota
	descendInsecure                // parent provided NSEC proof of no-DS
	descendNoCut                   // parent returned no DS records (child is not a zone)
	descendBogus                   // DS or DNSKEY verification failed
)

// descendInto attempts to walk one level of the chain: load and
// verify the DS rrset for childName at parentZone, then load and
// verify the DNSKEY rrset for childName, returning the new child
// dnssec.Zone if successful.
//
// When the parent returns no DS records, descendInto inspects the
// same response for an NSEC / NSEC3 proof of no-DS. A valid proof
// classifies childName as an Insecure delegation; absence of proof
// keeps the previous "treat as NoCut" behaviour so existing callers
// that ask for DS at a non-zone-cut name (e.g. qname itself) still
// proceed to leaf resolution.
func (v *Verifier) descendInto(ctx context.Context, parentZone *dnssec.Zone, parentName, childName string, result *Result) (*dnssec.Zone, *dnssec.DNSKey, descendStatus, error) {
	dsCount, err := v.loadRecords(ctx, parentZone, childName, types.TypeDS, result)
	if err != nil {
		return nil, nil, descendBogus, err
	}
	if dsCount == 0 {
		if proven, reason := v.proveNoDS(parentZone, childName); proven {
			result.InsecureReason = reason
			return nil, nil, descendInsecure, nil
		}
		return nil, nil, descendNoCut, nil
	}

	// DS rrset must be signed by parent zone's keys.
	dsOK, err := parentZone.VerifyRRSet(childName, types.TypeDS, dnssec.KeyModeNone, "")
	if err != nil {
		return nil, nil, descendBogus, fmt.Errorf("%w: %v", ErrVerifier, err)
	}
	if !dsOK {
		result.BogusReason = fmt.Sprintf("DS rrset for %s did not verify under %s", childName, parentName)
		return nil, nil, descendBogus, nil
	}

	// Load DNSKEY for child into a new zone parented at parentZone so
	// dnssec.Zone.verifyDelegationSigner can find DS records via the
	// parent pointer.
	childZone := dnssec.NewZone()
	childZone.SetParent(parentZone)
	if _, err := v.loadRecords(ctx, childZone, childName, types.TypeDNSKEY, result); err != nil {
		return nil, nil, descendBogus, err
	}

	// Manually match the child's KSK against one of the parent's DS
	// records before invoking KSK-mode verification.
	childKSK, err := matchKSKWithDS(childZone, parentZone, childName)
	if err != nil {
		result.BogusReason = err.Error()
		return nil, nil, descendBogus, nil
	}
	childZone.AddSEP(childName)

	dnskeyOK, err := childZone.VerifyRRSet(childName, types.TypeDNSKEY, dnssec.KeyModeKSK, "")
	if err != nil {
		return nil, nil, descendBogus, fmt.Errorf("%w: %v", ErrVerifier, err)
	}
	if !dnskeyOK {
		result.BogusReason = fmt.Sprintf("DNSKEY rrset for %s did not verify under its own KSK", childName)
		return nil, nil, descendBogus, nil
	}
	return childZone, childKSK, descendDescended, nil
}

// validateRoot loads the root DNSKEY rrset, matches it against the
// configured trust anchors, and verifies the rrset signature.
func (v *Verifier) validateRoot(ctx context.Context, result *Result) (*dnssec.Zone, *dnssec.DNSKey, error) {
	rootZone := dnssec.NewZone()
	if _, err := v.loadRecords(ctx, rootZone, ".", types.TypeDNSKEY, result); err != nil {
		return nil, nil, err
	}
	rootKSK, err := matchKSKWithAnchors(rootZone, v.anchors)
	if err != nil {
		result.Verdict = VerdictBogus
		result.BogusAt = "."
		result.BogusReason = err.Error()
		return nil, nil, nil // Bogus is a classified verdict, not a Validate error.
	}
	rootZone.AddSEP(".")
	ok, err := rootZone.VerifyRRSet(".", types.TypeDNSKEY, dnssec.KeyModeKSK, "")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrVerifier, err)
	}
	if !ok {
		result.Verdict = VerdictBogus
		result.BogusAt = "."
		result.BogusReason = "root DNSKEY rrset signature did not verify"
		return nil, nil, nil
	}
	return rootZone, rootKSK, nil
}

// loadRecords issues one resolver Query and appends every returned
// record to z. The presentation values are also captured in result.Evidence.
func (v *Verifier) loadRecords(ctx context.Context, z *dnssec.Zone, name string, qtype uint16, result *Result) (int, error) {
	records, err := v.resolver.Query(ctx, name, qtype)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, joinChainErr(err)
		}
		return 0, errors.Join(ErrResolver, err)
	}
	count := 0
	for _, rr := range records {
		z.AddRR(rr)
		switch rr.Type {
		case types.TypeDNSKEY:
			result.Evidence.DNSKEYs[rr.Label] = append(result.Evidence.DNSKEYs[rr.Label], rr.Value)
		case types.TypeDS:
			result.Evidence.DSes[rr.Label] = append(result.Evidence.DSes[rr.Label], rr.Value)
		case types.TypeRRSIG:
			key := rr.Label + "/" + qtypeMnemonic(qtype)
			result.Evidence.RRSIGs[key] = append(result.Evidence.RRSIGs[key], rr.Value)
		}
		if rr.Type == qtype {
			count++
		}
	}
	return count, nil
}

// matchKSKWithAnchors returns the first SEP-flagged DNSKEY in the root
// zone whose DS digest matches one of the configured trust anchors.
func matchKSKWithAnchors(rootZone *dnssec.Zone, anchors *dnssec.RootAnchors) (*dnssec.DNSKey, error) {
	if anchors == nil || len(anchors.DS) == 0 {
		return nil, errors.New("no trust anchors configured")
	}
	rrset := rootZone.FindRRSet(".", types.TypeDNSKEY)
	for _, rr := range rrset {
		k, ok := rr.Handler().(*dnssec.DNSKey)
		if !ok || !k.IsSecureEntryPoint() {
			continue
		}
		digestData, err := k.DSDigestData()
		if err != nil {
			continue
		}
		for _, anchor := range anchors.DS {
			if anchor.KeyTag != k.KeyTag || anchor.Algorithm != k.Algorithm {
				continue
			}
			digest, err := hex.DecodeString(anchor.Digest)
			if err != nil {
				continue
			}
			ds := dnssec.NewDS(nil, anchor.KeyTag, anchor.Algorithm, anchor.DigestType, digest)
			matched, err := ds.VerifyDigest(digestData)
			if err == nil && matched {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("%w", ErrTrustAnchorMismatch)
}

// matchKSKWithDS returns the first SEP-flagged DNSKEY in childZone
// whose DS digest matches one of the DS records present at parentZone
// under childName.
func matchKSKWithDS(childZone, parentZone *dnssec.Zone, childName string) (*dnssec.DNSKey, error) {
	dnskeys := childZone.FindRRSet(childName, types.TypeDNSKEY)
	dsSet := parentZone.FindRRSet(childName, types.TypeDS)
	if len(dnskeys) == 0 {
		return nil, fmt.Errorf("%w at %s", ErrNoDNSKEY, childName)
	}
	if len(dsSet) == 0 {
		return nil, fmt.Errorf("%w at %s", ErrNoDS, childName)
	}
	for _, rr := range dnskeys {
		k, ok := rr.Handler().(*dnssec.DNSKey)
		if !ok || !k.IsSecureEntryPoint() {
			continue
		}
		digestData, err := k.DSDigestData()
		if err != nil {
			continue
		}
		for _, dsRR := range dsSet {
			ds, ok := dsRR.Handler().(*dnssec.DS)
			if !ok {
				continue
			}
			if ds.KeyTag != k.KeyTag || ds.Algorithm != k.Algorithm {
				continue
			}
			matched, err := ds.VerifyDigest(digestData)
			if err == nil && matched {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("no DNSKEY at %s matched a DS in parent", childName)
}

// summarizeZone collects a [ZoneStep] for the result chain.
func summarizeZone(zoneName string, z *dnssec.Zone, ksk *dnssec.DNSKey) ZoneStep {
	step := ZoneStep{Zone: zoneName}
	for _, rr := range z.FindRRSet(zoneName, types.TypeDNSKEY) {
		k, ok := rr.Handler().(*dnssec.DNSKey)
		if !ok {
			continue
		}
		step.DNSKEYs = append(step.DNSKEYs, KeySummary{
			KeyTag:    k.KeyTag,
			Algorithm: k.Algorithm,
			SEP:       k.IsSecureEntryPoint(),
		})
	}
	for _, rr := range z.FindRRSet(zoneName, types.TypeDS) {
		ds, ok := rr.Handler().(*dnssec.DS)
		if !ok {
			continue
		}
		step.DSDigests = append(step.DSDigests, DSSummary{
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
		})
	}
	if ksk != nil {
		step.SignedBy = &KeySummary{
			KeyTag:    ksk.KeyTag,
			Algorithm: ksk.Algorithm,
			SEP:       ksk.IsSecureEntryPoint(),
		}
	}
	return step
}

// descendantZones returns the proper-suffix zone names of qname, from
// shallowest to deepest, excluding the root and qname itself.
//
//	qname = "www.example.com." → ["com.", "example.com.", "www.example.com."]
//
// The last entry (qname) is included so the descent loop can detect a
// "no DS at qname" no-cut case and stop one level above.
func descendantZones(qname string) []string {
	qname = normalizeQName(qname)
	if qname == "." {
		return nil
	}
	trimmed := strings.TrimSuffix(qname, ".")
	labels := strings.Split(trimmed, ".")
	out := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		out = append(out, strings.Join(labels[i:], ".")+".")
	}
	return out
}

// normalizeQName lowercases qname and ensures a trailing dot.
func normalizeQName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "."
	}
	if s[len(s)-1] != '.' {
		s += "."
	}
	return s
}

// qtypeMnemonic returns the canonical type name or "TYPE<n>" for
// unknown types, matching presentation-form RR rendering.
func qtypeMnemonic(t uint16) string {
	if name, err := types.RRTypeToString(t); err == nil {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// joinChainErr wraps ctx errors as ErrChainTimeout. context.Canceled
// also routes here because, from the verifier's point of view, both
// are "the chain walk could not finish".
func joinChainErr(err error) error {
	return errors.Join(ErrChainTimeout, err)
}

// Ensure zone.ResourceRecord is referenced so go vet does not warn on
// the otherwise-unused import in resolver.go on builds where Validate
// is the only chain.go consumer.
var _ = (*zone.ResourceRecord)(nil)
