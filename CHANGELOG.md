# Changelog

All notable changes to dnsdata-go are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `dnssec/` — NSEC / NSEC3 negative-proof primitives.
  - `CompareCanonicalNames` / `EqualCanonicalNames` (RFC 4034 §6.1
    canonical name comparator with wrap-around-safe ordering).
  - `NSEC.MatchesName` / `NSEC.CoversName` / `NSEC.ProvesNoData` /
    `NSEC.ProvesNoDS`.
  - `NSEC3.HasOptOut` / `NSEC3.CoversHash` / `NSEC3.ProvesNoData` /
    `NSEC3.ProvesNoDS`, plus `OwnerHashFromName` for decoding the
    leftmost base32hex label of an NSEC3 owner.
- `verifier/` — Insecure-delegation classification and leaf
  NODATA / NXDOMAIN classification.
  - `descendInto` consults the parent zone's NSEC / NSEC3 records when
    DS is absent: a valid proof flips the verdict to `Insecure` and
    records the proof source in the new `Result.InsecureReason`
    field. Supported proof shapes are matching NSEC, matching NSEC3,
    and covering NSEC3 with opt-out (RFC 5155 §6).
  - `Validate` leaf step consults NSEC / NSEC3 NODATA proofs (matching
    NSEC/NSEC3 with qtype absent from bitmap) and NXDOMAIN proofs
    (NSEC covering qname + wildcard-non-existence NSEC; or RFC 5155
    §8.4 three-record NSEC3 closest-encloser proof).
- Two new verdicts: `VerdictSecureNoData` (JSON `"secure-nodata"`)
  and `VerdictSecureNXDomain` (JSON `"secure-nxdomain"`). The four
  existing verdict strings are unchanged.
- `Result.InsecureReason` and `Result.NegativeReason` (`string`,
  JSON-omitempty).

### Changed

- `Verdict` enum widened from 4 to 6 states (`MUST 2` and `MUST 11` in
  DESIGN.md §4 updated to match). Consumers that only match on the
  original four strings still see them; consumers that want
  fine-grained secure-negative routing can read the new dashed names.
- `verifier/doc.go` "Out of scope" list no longer includes either the
  no-DS proof case or the leaf NODATA / NXDOMAIN cases.

## [0.1.0] — Initial release

End-to-end DNSSEC chain validation in pure Go, no external DNS
library, crypto from the standard library only. Walks the chain of
trust from a configured (or built-in) root trust anchor down to a
caller-supplied `(qname, qtype)`, returning a four-state verdict and
the raw DS / DNSKEY / RRSIG evidence consumed along the way.

### Added

- `types/` — RR type / class / opcode / rcode / DNSSEC algorithm
  enums and string conversion. Sentinel error types so callers can
  classify unknown values with `errors.Is`.
- `wire/` — DNS wire-format codec.
  - Domain-name encoder (`DomainNameToWire`) with RFC 1035 label /
    name length validation and RFC 4034 §6.2 canonical lower-casing.
  - Compression-pointer-aware name decoder (`ParseDomainName`) with
    cycle detection and a hop cap.
  - `Builder` for incremental wire-format assembly.
  - `ParseMessage` decodes header + question + answer / authority /
    additional sections into `RawMessage` and `RawRR`.
  - `RDataToString` per-type RDATA → presentation decoder for A,
    AAAA, NS, CNAME, PTR, DNAME, MX, TXT, SOA, SRV, CAA, DNSKEY,
    CDNSKEY, DS, CDS, RRSIG, NSEC, NSEC3, NSEC3PARAM. Unknown types
    use the RFC 3597 §5 generic form.
  - `BuildQuery` / `BuildQueryWithID` / `RandomQueryID` shared by
    both transports, producing an EDNS(0) OPT pseudo-RR with the DO
    bit set so responses include DNSSEC RRSIGs.
- `zone/` — zone-file parser, `ResourceRecord`, pluggable
  `RecordHandler` registry consumed by DNSSEC RR types.
- `dnssec/` — DNSSEC RR handlers and chain operations.
  - `DNSKey` — RFC 4034 Appendix B key-tag (incl. RSAMD5 special
    case), public-key materialisation, Sign / Verify across RSA
    PKCS#1 v1.5 (SHA-1 / SHA-256 / SHA-512), ECDSA P-256 / P-384,
    Ed25519.
  - `RRSig` / `DS` / `NSEC` / `NSEC3` / `NSEC3PARAM` with
    presentation parsing, wire encoding, type-bitmap codec
    (RFC 4034 §4.1.2), and RFC 5155 §5 NSEC3 hash.
  - `Zone` wraps `zone.Zone` with parent pointer, SEP set,
    RFC 4034 §6.2 canonical digest-target builder, and
    KSK / ZSK / CSK verification modes.
  - Root trust anchors — built-in KSK-2017 and KSK-2024 (IANA), and
    `RootAnchors` JSON shape shared with dnsdata-js for
    `~/.dnsdata/root-anchors.json` interop.
  - `RegisterHandlers()` opt-in registration (no `init()` side
    effects per DESIGN.md §4.21).
- `resolver/doh/` — RFC 8484 DoH client.
  - `NewClient`, `Query`, `QueryRaw`, `Resolve`. Provider failover
    (Google → Cloudflare → Quad9 by default), custom HTTP client
    injection, configurable User-Agent.
  - `Resolve` parses responses into `[]*zone.ResourceRecord`
    suitable for direct use as a `verifier.Resolver`.
- `resolver/auth/` — UDP / TCP plain-DNS client.
  - `NewClient`, `Query`, `QueryRaw`, `Resolve`. UDP-first with
    transparent TCP fallback on truncation (RFC 1035 §4.2.1),
    multi-server failover, per-server timeout in addition to
    context deadline, transaction-ID validation, configurable
    `Dialer` injection.
  - `Resolve` parses responses into `[]*zone.ResourceRecord` the
    same way DoH does.
  - Callers must supply server addresses explicitly via
    `WithServers`; the package does not read `/etc/resolv.conf`.
- `verifier/` — DNSSEC chain-of-trust walker.
  - `NewVerifier`, `Validate(ctx, qname, qtype)`.
  - Four-state `Verdict` (`secure | insecure | bogus |
    indeterminate`).
  - JSON-marshallable `Result` with chain summary, bogus-at /
    bogus-reason, evidence captured as presentation text.
  - `Resolver` interface + `ResolverFunc` adapter; works with both
    transports without a shim package.
  - Trust anchors caller-supplied, defaulting to the embedded
    IANA root anchors.

### Documentation

- `DESIGN.md` covers package layout, public API, MUST / SHOULD /
  MAY / MUST NOT contract, porting policy, and roadmap.
- `UPSTREAM_FEEDBACK.md` records both UF-NNN deviation fixes for
  dnsdata-js bugs encountered during porting (UF-001 … UF-004) and
  UP-NNN port-back proposals for new functionality shipped here
  (UP-001 verifier, UP-002 message parser + RData decoders, UP-003
  auth resolver).
- `CLAUDE.md` is the operating manual for further work in this
  repository with Claude Code.

### Not yet implemented

These are tracked in `verifier/doc.go` and the relevant UP entries:

- NSEC / NSEC3 negative-proof handling (used to distinguish Insecure
  from Bogus at no-DS delegations).
- CNAME / DNAME chasing.
- RFC 5011 automatic trust-anchor rollover.
- Cross-call DNSKEY / DS cache (SHOULD #13 in DESIGN.md).
- Helper converters to `miekg/dns.RR` (MAY #17).

[0.1.0]: https://github.com/shigeya/dnsdata-go/releases/tag/v0.1.0
