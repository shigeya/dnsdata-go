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
// Bogus or Insecure. A failing verdict carries a machine-readable
// [Result.ReasonCode]; [Result.Err] turns it into an error that wraps
// the matching sentinel ([ErrSigExpired], [ErrNoDS], …).
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
			setBogus(result, currentQname, "alias loop detected", CodeAliasLoop)
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
		if outcome.ReasonCode != "" {
			result.ReasonCode = outcome.ReasonCode
		}
		if outcome.NegativeReason != "" {
			result.NegativeReason = outcome.NegativeReason
		}
		if outcome.Wildcard != nil {
			result.Wildcard = outcome.Wildcard
		}
		if result.Verdict == VerdictSecure {
			result.Answer = outcome.Answer
		}
		return result, nil
	}

	// Alias chain longer than MaxAliasHops without resolving.
	setBogus(result, currentQname, fmt.Sprintf("alias chain exceeded %d hops", MaxAliasHops), CodeAliasLimit)
	return result, nil
}

// setBogus records a Bogus verdict decided outside a hop outcome.
func setBogus(result *Result, at, reason, code string) {
	result.Verdict = VerdictBogus
	result.BogusAt = at
	result.BogusReason = reason
	result.ReasonCode = code
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
	ReasonCode     string
	Alias          *AliasStep
	Wildcard       *WildcardInfo
	Answer         *Answer // the verified RRset of a terminal positive hop
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
		return bogusOutcome(result.BogusAt, result.BogusReason, result.ReasonCode), nil
	}
	if !zoneAlreadyInChain(result, ".") {
		result.Chain = append(result.Chain, summarizeZone(".", rootZone, nil, rootKSK))
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
				result.Chain = append(result.Chain, summarizeZone(childName, childZone, currentZone, childKSK))
			}
			currentZone = childZone
			currentName = childName
		case descendInsecure:
			return &hopOutcome{
				Verdict:        VerdictInsecure,
				InsecureAt:     childName,
				InsecureReason: result.InsecureReason,
				ReasonCode:     CodeNoDS,
			}, nil
		case descendBogus:
			reason := result.BogusReason
			if reason == "" {
				reason = "DS or DNSKEY verification failed"
			}
			return bogusOutcome(childName, reason, result.ReasonCode), nil
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
		check, err := v.checkRRSet(currentZone, qname, qtype, dnssec.KeyModeNone, result)
		if err != nil {
			return nil, err
		}
		if !check.ok {
			return bogusOutcome(currentName,
				fmt.Sprintf("RRSIG over %s/%s did not verify", qname, qtypeMnemonic(qtype)), check.code), nil
		}
		answer, err := buildAnswer(currentZone, qname, qtype)
		if err != nil {
			return nil, err
		}
		// Verified. If the covering RRSIG's Labels field indicates
		// wildcard synthesis, RFC 4035 §5.3.4 also requires a proof
		// that the next-closer name does not exist — otherwise the
		// wildcard rrset could be replayed at any non-existent name.
		if wc := detectWildcard(currentZone, qname, qtype); wc != nil {
			proven, reason := v.proveQnameNonExistence(currentZone, wc.NextCloser)
			if !proven {
				return bogusOutcome(currentName,
					fmt.Sprintf("wildcard synthesis at %s lacks non-existence proof for %s", wc.Source, wc.NextCloser),
					CodeWildcardProofMissing), nil
			}
			wc.ProofReason = reason
			return &hopOutcome{Verdict: VerdictSecure, Wildcard: wc, Answer: answer}, nil
		}
		return &hopOutcome{Verdict: VerdictSecure, Answer: answer}, nil
	}

	// Resolver placed records into currentZone but none matched
	// qtype. Look for an alias before declaring NODATA. DNAME goes
	// first: a DNAME answer also carries the CNAME synthesised from
	// it, and that CNAME has no RRSIG of its own (RFC 6672 §5.3.1), so
	// trying CNAME first would report the signed DNAME as Bogus. The
	// target is derived from the DNAME; the synthesised CNAME is not
	// used.
	if _, hop, err := v.tryDNAME(currentZone, currentName, qname, result); err != nil {
		return nil, err
	} else if hop != nil {
		return hop, nil
	}
	if _, hop, err := v.tryCNAME(currentZone, currentName, qname, result); err != nil {
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
		if belowDNAME(parentZone, childName) {
			// A name below a DNAME is never a zone cut (RFC 6672 §2.4),
			// and denial records for the DNAME owner say nothing about
			// it (RFC 6840 §4.1). Leaf resolution follows the DNAME.
			return nil, nil, descendNoCut, nil
		}
		if proven, reason := v.proveNoDS(parentZone, childName); proven {
			result.InsecureReason = reason
			return nil, nil, descendInsecure, nil
		}
		return nil, nil, descendNoCut, nil
	}

	// DS rrset must be signed by parent zone's keys.
	dsCheck, err := v.checkRRSet(parentZone, childName, types.TypeDS, dnssec.KeyModeNone, result)
	if err != nil {
		return nil, nil, descendBogus, err
	}
	if !dsCheck.ok {
		result.BogusReason = fmt.Sprintf("DS rrset for %s did not verify under %s", childName, parentName)
		result.ReasonCode = dsCheck.code
		return nil, nil, descendBogus, nil
	}

	// Load DNSKEY for child into a new zone parented at parentZone so
	// dnssec.Zone.verifyDelegationSigner can find DS records via the
	// parent pointer.
	childZone := v.newZone()
	childZone.SetParent(parentZone)
	if _, err := v.loadRecords(ctx, childZone, childName, types.TypeDNSKEY, result); err != nil {
		return nil, nil, descendBogus, err
	}

	// Manually match the child's KSK against one of the parent's DS
	// records before invoking KSK-mode verification.
	childKSK, err := matchKSKWithDS(childZone, parentZone, childName)
	if err != nil {
		result.BogusReason = err.Error()
		result.ReasonCode = keyMatchCode(err)
		return nil, nil, descendBogus, nil
	}
	childZone.AddSEP(childName)

	dnskeyCheck, err := v.checkRRSet(childZone, childName, types.TypeDNSKEY, dnssec.KeyModeKSK, result)
	if err != nil {
		return nil, nil, descendBogus, err
	}
	if !dnskeyCheck.ok {
		result.BogusReason = fmt.Sprintf("DNSKEY rrset for %s did not verify under its own KSK", childName)
		result.ReasonCode = dnskeyCheck.code
		return nil, nil, descendBogus, nil
	}
	return childZone, childKSK, descendDescended, nil
}

// keyMatchCode names why [matchKSKWithDS] found no key.
func keyMatchCode(err error) string {
	switch {
	case errors.Is(err, ErrNoDNSKEY):
		return CodeNoDNSKEY
	case errors.Is(err, ErrNoDS):
		return CodeNoDS
	}
	return CodeDSMismatch
}

// belowDNAME reports whether z holds a DNAME at a proper ancestor of
// name. Whether it verifies is left to leaf resolution: skipping a
// no-DS proof can only make the verdict stricter.
func belowDNAME(z *dnssec.Zone, name string) bool {
	for _, anc := range ancestorsOf(name) {
		if dnssec.EqualCanonicalNames(anc, name) {
			continue
		}
		if len(z.FindRRSet(anc, types.TypeDNAME)) > 0 {
			return true
		}
	}
	return false
}

// validateRoot loads the root DNSKEY rrset, matches it against the
// configured trust anchors, and verifies the rrset signature.
func (v *Verifier) validateRoot(ctx context.Context, result *Result) (*dnssec.Zone, *dnssec.DNSKey, error) {
	rootZone := v.newZone()
	if _, err := v.loadRecords(ctx, rootZone, ".", types.TypeDNSKEY, result); err != nil {
		return nil, nil, err
	}
	rootKSK, err := matchKSKWithAnchors(rootZone, v.anchors)
	if err != nil {
		// Bogus is a classified verdict, not a Validate error.
		setBogus(result, ".", err.Error(), CodeTrustAnchorMismatch)
		return nil, nil, nil
	}
	rootZone.AddSEP(".")
	check, err := v.checkRRSet(rootZone, ".", types.TypeDNSKEY, dnssec.KeyModeKSK, result)
	if err != nil {
		return nil, nil, err
	}
	if !check.ok {
		setBogus(result, ".", "root DNSKEY rrset signature did not verify", check.code)
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
			return v.applyRecords(cached, z, name, qtype, result), nil
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
	return v.applyRecords(resp.Records, z, name, qtype, result), nil
}

// applyRecords appends each record to z, updates result.Evidence for
// the DNSSEC-bookkeeping types, and returns the count of records of
// type qtype owned by name. Shared by the resolver-miss and cache-hit
// paths so the two produce indistinguishable bookkeeping.
//
// The owner check matters for recursive resolvers: they follow a CNAME
// or DNAME themselves and put the target's rrset (same type, different
// owner) into the same answer. Counting those would make the caller
// look for a qname rrset that is not there.
func (v *Verifier) applyRecords(records []*zone.ResourceRecord, z *dnssec.Zone, name string, qtype uint16, result *Result) int {
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
		if rr.Type == qtype && dnssec.EqualCanonicalNames(rr.Label, name) {
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
		k, ok := rootZone.Handler(rr).(*dnssec.DNSKey)
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
		k, ok := childZone.Handler(rr).(*dnssec.DNSKey)
		if !ok || !k.IsSecureEntryPoint() {
			continue
		}
		digestData, err := k.DSDigestData()
		if err != nil {
			continue
		}
		for _, dsRR := range dsSet {
			ds, ok := parentZone.Handler(dsRR).(*dnssec.DS)
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

// summarizeZone collects a [ZoneStep] for the result chain. The DS
// records are read from parent, which the descent loaded them into
// (nil for the root).
func summarizeZone(zoneName string, z, parent *dnssec.Zone, ksk *dnssec.DNSKey) ZoneStep {
	step := ZoneStep{Zone: zoneName}
	for _, rr := range z.FindRRSet(zoneName, types.TypeDNSKEY) {
		k, ok := z.Handler(rr).(*dnssec.DNSKey)
		if !ok {
			continue
		}
		step.DNSKEYs = append(step.DNSKEYs, KeySummary{
			KeyTag:    k.KeyTag,
			Algorithm: k.Algorithm,
			SEP:       k.IsSecureEntryPoint(),
		})
	}
	step.DSDigests = summarizeDS(zoneName, parent)
	if ksk != nil {
		step.SignedBy = &KeySummary{
			KeyTag:    ksk.KeyTag,
			Algorithm: ksk.Algorithm,
			SEP:       ksk.IsSecureEntryPoint(),
		}
	}
	return step
}

// summarizeDS lists the DS records for zoneName held by parent.
func summarizeDS(zoneName string, parent *dnssec.Zone) []DSSummary {
	if parent == nil {
		return nil
	}
	var out []DSSummary
	for _, rr := range parent.FindRRSet(zoneName, types.TypeDS) {
		ds, ok := parent.Handler(rr).(*dnssec.DS)
		if !ok {
			continue
		}
		out = append(out, DSSummary{
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
		})
	}
	return out
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

// newZone returns an empty zone whose RRSIG checks use the verifier's
// clock (RFC 4035 §5.3.1: a signature outside its validity window does
// not verify) and whose handlers come from the verifier's registry.
func (v *Verifier) newZone() *dnssec.Zone {
	z := dnssec.NewZone()
	z.SetClock(v.now)
	z.SetRegistry(v.registry)
	return z
}

// qtypeMnemonic returns the canonical type name or "TYPE<n>" for
// unknown types, matching presentation-form RR rendering.
func qtypeMnemonic(t uint16) string {
	return types.RRTypeName(t)
}

// joinChainErr wraps ctx errors as ErrChainTimeout. context.Canceled
// also routes here because, from the verifier's point of view, both
// are "the chain walk could not finish".
func joinChainErr(err error) error {
	return errors.Join(ErrChainTimeout, err)
}
