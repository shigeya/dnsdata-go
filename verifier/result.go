package verifier

// Result is the outcome of [Verifier.Validate]. It is intentionally
// JSON-friendly (DESIGN.md MUST 10): every field uses primitive types
// or other JSON-friendly structs from this package, and the public
// field tags match the cross-language schema agreed with dnsdata-js.
type Result struct {
	// Verdict is the four-state classification for this query.
	Verdict Verdict `json:"verdict"`

	// Chain enumerates each zone visited from root to the qname's
	// zone, with the keys / DS digests used at each step.
	Chain []ZoneStep `json:"chain"`

	// InsecureAt names the zone where the secure chain broke into an
	// insecure delegation (NSEC proof of no-DS). Empty for non-Insecure
	// verdicts.
	InsecureAt string `json:"insecureAt,omitempty"`

	// InsecureReason is a short, human-readable explanation paired with
	// InsecureAt — e.g. which NSEC/NSEC3 record produced the proof.
	// Empty for non-Insecure verdicts.
	InsecureReason string `json:"insecureReason,omitempty"`

	// NegativeReason is a short, human-readable explanation paired
	// with [VerdictSecureNoData] and [VerdictSecureNXDomain] —
	// e.g. which NSEC/NSEC3 record(s) produced the proof. Empty for
	// other verdicts.
	NegativeReason string `json:"negativeReason,omitempty"`

	// BogusAt names the zone where validation failed. Empty for
	// non-Bogus verdicts.
	BogusAt string `json:"bogusAt,omitempty"`

	// BogusReason is a short, human-readable explanation paired with
	// BogusAt (e.g. "DS digest mismatch", "RRSIG expired"). Empty for
	// non-Bogus verdicts.
	BogusReason string `json:"bogusReason,omitempty"`

	// Evidence carries the raw records that drove the verdict so
	// downstream consumers (mailsec-probe Signals) can re-render them
	// without re-querying. DESIGN.md MUST 5.
	Evidence Evidence `json:"evidence"`

	// Aliases enumerates every CNAME / DNAME hop the chain walker
	// followed before reaching the terminal qname. Empty when the
	// original qname has the requested rrset (or a negative proof)
	// directly. The terminal qname is the From field of the last
	// step's target, NOT a step itself.
	Aliases []AliasStep `json:"aliases,omitempty"`

	// Wildcard is non-nil when the terminal positive answer was
	// produced by wildcard expansion (RFC 4035 §5.3.4). Carries the
	// reconstructed wildcard owner, the closest encloser, the
	// next-closer name whose non-existence was proven, and the proof
	// source. The verdict on a properly-proven wildcard remains
	// [VerdictSecure]; consumers that need to distinguish "real
	// rrset" from "wildcard-synthesised rrset" check this field.
	Wildcard *WildcardInfo `json:"wildcard,omitempty"`
}

// WildcardInfo describes a wildcard-synthesised positive answer.
//
// Source is the reconstructed wildcard owner the validator used for
// digest computation (e.g. "*.example.com."). ClosestEncloser is the
// deepest ancestor of the qname that exists in the zone (the same
// labels that, prefixed with "*.", form the wildcard owner).
// NextCloser is the closest-encloser's child along qname's path —
// the name whose non-existence the validator just proved via NSEC or
// NSEC3.
type WildcardInfo struct {
	Source          string `json:"source"`
	ClosestEncloser string `json:"closestEncloser"`
	NextCloser      string `json:"nextCloser"`
	ProofReason     string `json:"proofReason"`
}

// AliasStep records one CNAME or DNAME hop encountered during
// resolution. Each hop is a signed redirect from a name in a zone to
// a target name (possibly in a different zone), reified for both
// audit and for downstream consumers that want to render the journey.
type AliasStep struct {
	// Type is "cname" or "dname".
	Type string `json:"type"`

	// From is the name that produced the alias (i.e. the CNAME owner
	// or DNAME owner).
	From string `json:"from"`

	// Target is the rewritten name the chain walker continues with
	// after this hop.
	Target string `json:"target"`

	// Zone is the zone that signed this alias record.
	Zone string `json:"zone"`

	// Verdict is the classification of this hop in isolation —
	// useful for callers that want to know exactly which hop turned
	// Insecure or Bogus when the final verdict is the worst-of.
	Verdict Verdict `json:"verdict"`
}

// ZoneStep summarises one zone on the chain.
type ZoneStep struct {
	// Zone is the zone name including the trailing dot (e.g. "com.").
	Zone string `json:"zone"`

	// DNSKEYs lists the DNSKEY (key-tag, algorithm, KSK/ZSK flag) of
	// every key seen in this zone, in zone-file order.
	DNSKEYs []KeySummary `json:"dnskeys,omitempty"`

	// DSDigests lists every DS digest that authorised the descent
	// into this zone. Empty for the root step.
	DSDigests []DSSummary `json:"dsDigests,omitempty"`

	// SignedBy carries the (key-tag, algorithm) pair of the DNSKEY
	// that verified the DNSKEY rrset at this zone (the KSK). Empty if
	// validation did not reach this step.
	SignedBy *KeySummary `json:"signedBy,omitempty"`
}

// KeySummary identifies a DNSKEY without exposing the raw key bytes
// (those live in Evidence).
type KeySummary struct {
	KeyTag    uint16 `json:"keyTag"`
	Algorithm uint8  `json:"algorithm"`
	SEP       bool   `json:"sep"`
}

// DSSummary identifies a DS record without exposing the raw digest
// bytes (those live in Evidence).
type DSSummary struct {
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`
}

// Evidence carries the raw textual rrset values used during
// validation. Each entry is a presentation-form rrset (the same
// string a zone file would contain). Keeping presentation form rather
// than parsed handlers means the caller can JSON-serialise Result
// without writing custom marshallers for every handler type.
type Evidence struct {
	// DNSKEYs maps zone name → list of DNSKEY presentation values.
	DNSKEYs map[string][]string `json:"dnskeys,omitempty"`

	// DSes maps zone name → list of DS presentation values.
	DSes map[string][]string `json:"dses,omitempty"`

	// RRSIGs maps "<name>/<rrtype>" → list of RRSIG presentation
	// values. The composite key keeps signatures separable per rrset
	// so consumers can re-render them in their original context.
	RRSIGs map[string][]string `json:"rrsigs,omitempty"`
}
