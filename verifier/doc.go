// Package verifier walks a DNSSEC chain of trust from the root zone
// down to a requested (qname, qtype), classifies the result as one of
// Secure / Insecure / Bogus / Indeterminate, and surfaces the raw
// evidence (DS / DNSKEY / RRSIG records) used along the way.
//
// Architecture
//
// The chain walker is intentionally decoupled from any specific
// transport. A caller-supplied [Resolver] returns the records for a
// (name, qtype) tuple; the verifier reassembles them into per-zone
// [github.com/shigeya/dnsdata-go/dnssec.Zone] instances and reuses the
// signature-verification primitives from that package. As a result
// the same Verifier can be driven by DoH (resolver/doh), authoritative
// queries (resolver/auth, future), or any in-memory test fixture.
//
// Scope
//
// v0.1.0 ships positive validation: every zone on the path from root
// to qname has a usable DNSKEY rrset and the qname's RRset is signed
// by that zone's keys.
//
// v0.2.0 adds NSEC / NSEC3 negative proofs for the no-DS case. When a
// parent zone returns no DS for a child name AND its response carries
// an NSEC/NSEC3 record that validly proves DS does not exist, the
// chain walker classifies that delegation as [VerdictInsecure] (and
// records the proof source in [Result.InsecureReason]) rather than
// continuing as if the name were not a zone cut. Supported proof
// shapes:
//
//   - Matching NSEC with NS bit set, DS / SOA bits unset.
//   - Matching NSEC3 with the same bitmap shape.
//   - Covering NSEC3 with the opt-out flag set (RFC 5155 §6).
//
// Out of scope (tracked separately):
//
//   - NSEC / NSEC3 proofs of NODATA and NXDOMAIN at the leaf (the
//     leaf step still returns [VerdictIndeterminate] when the qname
//     has no rrset).
//   - CNAME / DNAME chasing.
//   - RFC 5011 trust-anchor key rollover.
//   - Caching of DNSKEY / DS rrsets across calls (the SHOULD #13 cache
//     hook in DESIGN.md §4 will land alongside the cache milestone).
//
// Per the design rules in CLAUDE.md / DESIGN.md, the verifier holds no
// global mutable state and writes nothing to the filesystem / stdout
// / stderr by default. Multiple [Verifier] instances are independent
// and safe to use concurrently.
package verifier
