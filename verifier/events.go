package verifier

import (
	"fmt"

	"github.com/shigeya/dnsdata-go/types"
)

// StepEvent is one step of a Validate call, streamed to the handler set
// with [WithStepHandler] (DESIGN.md SHOULD 14), e.g. for verbose
// logging. Kind is one of the Step constants; what Zone and Detail hold
// depends on it (see each constant). Sig is set only on [StepSig].
type StepEvent struct {
	Kind   string
	Zone   string
	Sig    *SigCheck
	Detail string
}

// StepEvent kinds, in the order a walk produces them.
const (
	// StepQuery: a query is sent to the resolver. Zone is the queried
	// name, Detail its type mnemonic.
	StepQuery = "query"
	// StepCacheHit: the [Cache] answered instead. Zone and Detail as
	// for StepQuery.
	StepCacheHit = "cache-hit"
	// StepDS: the DS rrset of the descent into Zone was checked. Detail
	// is "verified" or the failure's reason code (as in
	// [Result.ReasonCode]; "error" when the check could not be made).
	StepDS = "ds"
	// StepDNSKEY: the DNSKEY rrset of Zone was checked. Detail as for
	// StepDS.
	StepDNSKEY = "dnskey"
	// StepZone: a step for Zone was added to [Result.Chain]. Each zone
	// is reported once, root first.
	StepZone = "zone"
	// StepSig: a [SigCheck] was added to the chain step of Zone. Sig is
	// a copy of it; the sig events of a Validate call correspond one to
	// one to the SigChecks of its Result.Chain.
	StepSig = "sig"
	// StepAlias: a CNAME or DNAME was followed. Zone is the zone that
	// signed it, Detail "<type> <from> -> <target>".
	StepAlias = "alias"
	// StepInsecure: the verdict is Insecure. Zone is InsecureAt, Detail
	// "<reason code>: <reason>".
	StepInsecure = "insecure"
	// StepBogus: the verdict is Bogus. Zone is BogusAt, Detail as for
	// StepInsecure.
	StepBogus = "bogus"
	// StepAnswer: the last event of a Validate call that returns no
	// error. Zone is the final query name (after aliases), Detail the
	// verdict ([Verdict.String]).
	StepAnswer = "answer"
)

// WithStepHandler streams the steps of every Validate call to h. h runs
// synchronously on the goroutine that called Validate, never after
// Validate returns, so a slow handler slows validation; a Verifier
// shared between goroutines calls h from each of them. A nil h (the
// default) costs nothing. The library itself never writes to stdout or
// stderr; routing events there is the caller's choice.
func WithStepHandler(h func(StepEvent)) Option {
	return func(v *Verifier) { v.onStep = h }
}

// emit hands e to the step handler, if any.
func (v *Verifier) emit(kind, zoneName, detail string) {
	if v.onStep != nil {
		v.onStep(StepEvent{Kind: kind, Zone: zoneName, Detail: detail})
	}
}

// emitLookup reports a query or cache hit for (name, qtype).
func (v *Verifier) emitLookup(kind, name string, qtype uint16) {
	if v.onStep != nil {
		v.emit(kind, name, qtypeMnemonic(qtype))
	}
}

// emitSig reports a SigCheck added to the step of zoneName.
func (v *Verifier) emitSig(zoneName string, c SigCheck) {
	if v.onStep != nil {
		v.onStep(StepEvent{Kind: StepSig, Zone: zoneName, Sig: &c})
	}
}

// emitRRSetCheck reports the outcome of a DS or DNSKEY rrset check.
func (v *Verifier) emitRRSetCheck(name string, rrtype uint16, c rrsetCheck, err error) {
	if v.onStep == nil {
		return
	}
	var kind string
	switch rrtype {
	case types.TypeDS:
		kind = StepDS
	case types.TypeDNSKEY:
		kind = StepDNSKEY
	default:
		return
	}
	detail := SigVerified
	switch {
	case !c.ok && c.code != "":
		detail = c.code
	case err != nil:
		detail = "error"
	}
	v.emit(kind, name, detail)
}

// emitAlias reports an alias hop.
func (v *Verifier) emitAlias(a *AliasStep) {
	if v.onStep != nil {
		v.emit(StepAlias, a.Zone, fmt.Sprintf("%s %s -> %s", a.Type, a.From, a.Target))
	}
}

// emitVerdict reports the classification of result, ending with
// StepAnswer.
func (v *Verifier) emitVerdict(result *Result, qname string) {
	if v.onStep == nil {
		return
	}
	switch result.Verdict {
	case VerdictBogus:
		v.emit(StepBogus, result.BogusAt, result.ReasonCode+": "+result.BogusReason)
	case VerdictInsecure:
		v.emit(StepInsecure, result.InsecureAt, result.ReasonCode+": "+result.InsecureReason)
	}
	v.emit(StepAnswer, qname, result.Verdict.String())
}
