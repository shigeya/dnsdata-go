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

// MaxAliasHops caps the number of CNAME / DNAME redirects a single
// Validate call is willing to follow. RFC 1035 leaves the limit to
// implementations; popular validators settle near 8–16. We use 10 and
// also detect repeated qnames (a tighter loop indicator).
const MaxAliasHops = 10

// Validate walks the DNSSEC chain of trust from the root zone down to
// (qname, qtype), classifies the outcome, and returns the evidence
// gathered along the way.
//
// CNAME and DNAME redirections are chased transparently up to
// [MaxAliasHops] steps. Each hop is recorded in [Result.Aliases] and
// the final Verdict is the worst-of across all hops: any Insecure
// hop yields Insecure, any Bogus hop yields Bogus, and so on. Loops
// (a qname repeating in the chain) are reported as Bogus.
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
	result := &Result{
		Verdict:  VerdictIndeterminate,
		Evidence: Evidence{DNSKEYs: map[string][]string{}, DSes: map[string][]string{}, RRSIGs: map[string][]string{}},
	}

	currentQname := normalizeQName(qname)
	seen := map[string]bool{}
	combined := VerdictIndeterminate
	var combinedSet bool

	for hop := 0; hop <= MaxAliasHops; hop++ {
		if err := ctx.Err(); err != nil {
			return result, joinChainErr(err)
		}
		if seen[currentQname] {
			result.Verdict = VerdictBogus
			result.BogusAt = currentQname
			result.BogusReason = "alias loop detected"
			return result, nil
		}
		seen[currentQname] = true

		outcome, err := v.validateOneHop(ctx, currentQname, qtype, result)
		if err != nil {
			return result, err
		}

		if !combinedSet {
			combined = outcome.Verdict
			combinedSet = true
		} else {
			combined = combineVerdicts(combined, outcome.Verdict)
		}

		if outcome.Alias != nil {
			outcome.Alias.Verdict = outcome.Verdict
			result.Aliases = append(result.Aliases, *outcome.Alias)
			currentQname = outcome.Alias.Target
			continue
		}

		result.Verdict = combined
		// Carry forward the terminal hop's diagnostic strings so the
		// caller learns *why* the worst hop failed (if any) or which
		// negative proof produced a Secure-negative verdict. The
		// terminal hop's values overwrite anything set earlier so the
		// reported location matches the verdict.
		if outcome.BogusAt != "" {
			result.BogusAt = outcome.BogusAt
		}
		if outcome.BogusReason != "" {
			result.BogusReason = outcome.BogusReason
		}
		if outcome.InsecureAt != "" {
			result.InsecureAt = outcome.InsecureAt
		}
		if outcome.InsecureReason != "" {
			result.InsecureReason = outcome.InsecureReason
		}
		if outcome.NegativeReason != "" {
			result.NegativeReason = outcome.NegativeReason
		}
		if outcome.Wildcard != nil {
			result.Wildcard = outcome.Wildcard
		}
		return result, nil
	}

	// Alias chain longer than MaxAliasHops without resolving.
	result.Verdict = VerdictBogus
	result.BogusAt = currentQname
	result.BogusReason = fmt.Sprintf("alias chain exceeded %d hops", MaxAliasHops)
	return result, nil
}

// hopOutcome is the inner result of one [validateOneHop] call.
//
// Exactly one of {terminal verdict, Alias} is meaningful: when Alias
// is non-nil the caller should redirect to Alias.Target and run the
// next hop; otherwise the hop is terminal and Verdict is the answer.
type hopOutcome struct {
	Verdict        Verdict
	BogusAt        string
	BogusReason    string
	InsecureAt     string
	InsecureReason string
	NegativeReason string
	Alias          *AliasStep
	Wildcard       *WildcardInfo
}

// validateOneHop runs a single chain-walk + leaf-resolution against
// (qname, qtype). It mutates result.Chain / result.Evidence as it
// walks, but does NOT touch result.Verdict / result.Aliases — those
// are the caller's responsibility.
func (v *Verifier) validateOneHop(ctx context.Context, qname string, qtype uint16, result *Result) (*hopOutcome, error) {
	// Step 1: load and validate the root zone.
	rootZone, rootKSK, err := v.validateRoot(ctx, result)
	if err != nil {
		return nil, err
	}
	if rootZone == nil {
		// validateRoot set result.Verdict / Bogus*; mirror into the
		// outcome so the outer loop can combine verdicts.
		return &hopOutcome{
			Verdict:     VerdictBogus,
			BogusAt:     result.BogusAt,
			BogusReason: result.BogusReason,
		}, nil
	}
	if !zoneAlreadyInChain(result, ".") {
		result.Chain = append(result.Chain, summarizeZone(".", rootZone, rootKSK))
	}

	// Step 2: descend through each label boundary that's actually a
	// zone cut.
	currentZone := rootZone
	currentName := "."
	for _, childName := range descendantZones(qname) {
		if err := ctx.Err(); err != nil {
			return nil, joinChainErr(err)
		}
		childZone, childKSK, status, err := v.descendInto(ctx, currentZone, currentName, childName, result)
		if err != nil {
			return nil, err
		}
		switch status {
		case descendDescended:
			if !zoneAlreadyInChain(result, childName) {
				result.Chain = append(result.Chain, summarizeZone(childName, childZone, childKSK))
			}
			currentZone = childZone
			currentName = childName
		case descendInsecure:
			return &hopOutcome{
				Verdict:        VerdictInsecure,
				InsecureAt:     childName,
				InsecureReason: result.InsecureReason,
			}, nil
		case descendBogus:
			reason := result.BogusReason
			if reason == "" {
				reason = "DS or DNSKEY verification failed"
			}
			return &hopOutcome{
				Verdict:     VerdictBogus,
				BogusAt:     childName,
				BogusReason: reason,
			}, nil
		case descendNoCut:
			// childName is not a zone cut under currentZone — most
			// often this is qname itself (handled by falling through
			// to leaf resolution after the loop), but it can also be
			// an empty non-terminal between two real cuts (e.g.
			// "ad.jp." between "jp." and "wide.ad.jp."). Continue so
			// the loop tries deeper descendants against the same
			// currentZone; descent only finalises when descendantZones
			// is exhausted, or a real cut is found and verified.
			continue
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, joinChainErr(err)
	}
	return v.resolveLeaf(ctx, currentZone, currentName, qname, qtype, result)
}

// resolveLeaf handles the final step of a hop: load qname/qtype into
// currentZone and either return a terminal verdict or surface an
// alias hop. CNAME at qname and DNAME at any ancestor of qname are
// followed; missing rrsets fall through to NSEC / NSEC3 negative
// proofs.
func (v *Verifier) resolveLeaf(ctx context.Context, currentZone *dnssec.Zone, currentName, qname string, qtype uint16, result *Result) (*hopOutcome, error) {
	added, err := v.loadRecords(ctx, currentZone, qname, qtype, result)
	if err != nil {
		return nil, err
	}
	if added > 0 {
		ok, err := currentZone.VerifyRRSet(qname, qtype, dnssec.KeyModeNone, "")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrVerifier, err)
		}
		if !ok {
			return &hopOutcome{
				Verdict:     VerdictBogus,
				BogusAt:     currentName,
				BogusReason: fmt.Sprintf("RRSIG over %s/%s did not verify", qname, qtypeMnemonic(qtype)),
			}, nil
		}
		// Verified. If the covering RRSIG's Labels field indicates
		// wildcard synthesis, RFC 4035 §5.3.4 also requires a proof
		// that the next-closer name does not exist — otherwise the
		// wildcard rrset could be replayed at any non-existent name.
		if wc := detectWildcard(currentZone, qname, qtype); wc != nil {
			proven, reason := v.proveQnameNonExistence(currentZone, wc.NextCloser)
			if !proven {
				return &hopOutcome{
					Verdict:     VerdictBogus,
					BogusAt:     currentName,
					BogusReason: fmt.Sprintf("wildcard synthesis at %s lacks non-existence proof for %s", wc.Source, wc.NextCloser),
				}, nil
			}
			wc.ProofReason = reason
			return &hopOutcome{Verdict: VerdictSecure, Wildcard: wc}, nil
		}
		return &hopOutcome{Verdict: VerdictSecure}, nil
	}

	// Resolver placed records into currentZone but none matched
	// qtype. Look for an alias before declaring NODATA.
	if alias, hop, err := v.tryCNAME(currentZone, currentName, qname); err != nil {
		return nil, err
	} else if hop != nil {
		return hop, nil
	} else if alias != nil {
		// alias != nil but hop == nil should not happen; defensive.
		_ = alias
	}
	if _, hop, err := v.tryDNAME(currentZone, currentName, qname); err != nil {
		return nil, err
	} else if hop != nil {
		return hop, nil
	}

	// No alias — fall back to negative-existence proofs.
	if proven, reason := v.proveNoData(currentZone, qname, qtype); proven {
		return &hopOutcome{
			Verdict:        VerdictSecureNoData,
			NegativeReason: reason,
		}, nil
	}
	if proven, reason := v.proveNXDomain(currentZone, qname); proven {
		return &hopOutcome{
			Verdict:        VerdictSecureNXDomain,
			NegativeReason: reason,
		}, nil
	}
	return &hopOutcome{Verdict: VerdictIndeterminate}, nil
}

// zoneAlreadyInChain reports whether result.Chain already contains a
// ZoneStep for zoneName. Used during alias chasing so multiple hops
// don't duplicate "." and "com." entries.
func zoneAlreadyInChain(result *Result, zoneName string) bool {
	for _, step := range result.Chain {
		if step.Zone == zoneName {
			return true
		}
	}
	return false
}

// combineVerdicts merges a per-hop verdict into the running total
// using a worst-of policy. The ordering, from "best" to "worst", is:
//
//	Secure < SecureNoData ~ SecureNXDomain < Indeterminate < Insecure < Bogus
//
// Secure-negative variants are treated as equivalent to Secure for
// the purposes of merging because both indicate "the chain reached
// a signed conclusion"; the kind of secure result the chain produced
// is preserved only when nothing worse follows.
func combineVerdicts(a, b Verdict) Verdict {
	if a == VerdictBogus || b == VerdictBogus {
		return VerdictBogus
	}
	if a == VerdictInsecure || b == VerdictInsecure {
		return VerdictInsecure
	}
	if a == VerdictIndeterminate || b == VerdictIndeterminate {
		return VerdictIndeterminate
	}
	// Both are some flavour of Secure. Prefer the most specific —
	// if either side is a secure-negative, surface that (callers
	// generally want to know "the redirect terminated at a NODATA").
	if b == VerdictSecure {
		return a
	}
	return b
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
//
// When a [Cache] is attached (via [WithCache]) the lookup goes through
// the cache first; a hit reuses the previously fetched records and
// skips the resolver entirely. Both hits and fresh fetches feed the
// same [applyRecords] path so result.Evidence is populated identically
// in either case. Resolver errors are NEVER cached.
func (v *Verifier) loadRecords(ctx context.Context, z *dnssec.Zone, name string, qtype uint16, result *Result) (int, error) {
	if v.cache != nil {
		if cached, ok := v.cache.Get(name, qtype); ok {
			return v.applyRecords(cached, z, qtype, result), nil
		}
	}
	resp, err := v.resolver.Query(ctx, name, qtype)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, joinChainErr(err)
		}
		return 0, errors.Join(ErrResolver, err)
	}
	// Non-zero RCODE is surfaced as data by the resolver layer but is a
	// hard error for chain validation (RFC 4035 §5): we cannot prove
	// anything from a SERVFAIL or REFUSED. NXDOMAIN (3) and NODATA
	// (records empty, RCODE 0) are handled downstream as "no records
	// present" and need their own NSEC/NSEC3 proofs.
	if resp.RCode != 0 && resp.RCode != 3 {
		return 0, errors.Join(ErrResolver, fmt.Errorf("RCODE=%d", resp.RCode))
	}
	if v.cache != nil {
		v.cache.Put(name, qtype, resp.Records)
	}
	return v.applyRecords(resp.Records, z, qtype, result), nil
}

// applyRecords appends each record to z, updates result.Evidence for
// the DNSSEC-bookkeeping types, and returns the count of records
// matching qtype. Shared by the resolver-miss and cache-hit paths so
// the two produce indistinguishable bookkeeping.
func (v *Verifier) applyRecords(records []*zone.ResourceRecord, z *dnssec.Zone, qtype uint16, result *Result) int {
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
	return count
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

