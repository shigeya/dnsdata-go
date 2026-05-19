# Changelog

All notable changes to dnsdata-go are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] — 2026-05-19

### Added

- `verifier`: pluggable `Cache` interface and built-in `MemoryCache`
  attached via `WithCache(c Cache)`. The verifier consults the cache
  before every `Resolver.Query` and stores successful responses
  (including NODATA) back into it; resolver errors are never cached.
  Sharing one `Cache` across `Validate` calls lets a batch run reuse
  root and TLD DNSKEY/DS rrsets, satisfying DESIGN.md §4 SHOULD #13.
  Ported to dnsdata-js as
  [#25](https://github.com/shigeya/dnsdata-js/pull/25) (UP-008).

## [0.3.1] — 2026-05-19

### Changed

- `resolver/doh`: default provider order changed from
  `Google → Cloudflare → Quad9` to **`Cloudflare → Google → Quad9`**.
  The new order prioritises tail-latency stability (Cloudflare's
  anycast PoP footprint is more evenly distributed worldwide,
  particularly in Asia/Pacific), keeps Google as a reliable fallback,
  and continues to place Quad9 last because its malicious-domain block
  list returns NXDOMAIN for filtered names — a behaviour that should
  not affect the common case.

  Callers that explicitly configured providers via `WithProviders` are
  unaffected. The full rationale, including provider-by-provider
  notes, is now documented in the `resolver/doh` package doc.

  No code-level API changed.


## [0.3.0] — 2026-05-19

P9 RR handler set — sixteen legacy RR handlers and the EDNS(0) OPT
pseudo-RR codec ported from dnsdata-js, all reachable through the new
`zone.RegisterHandlers()` opt-in entrypoint (no `init()` side effects,
DESIGN.md §4.21). Consumers that want every bundled handler call

```go
zone.RegisterHandlers()
dnssec.RegisterHandlers()
```

which is equivalent to dnsdata-js's `registerAllHandlers()`.

### Added

- `zone`: P9 Batch 1 — `TLSA` (RFC 6698, type 52), `SMIMEA`
  (RFC 8162, type 53), and `SSHFP` (RFC 4255, type 44) RR handlers.
  TLSA and SMIMEA share one struct since their wire and presentation
  formats are byte-for-byte identical; `smimeaFactory` forwards to
  `tlsaFactory`. Closes
  [#6](https://github.com/shigeya/dnsdata-go/issues/6); part of
  [#5](https://github.com/shigeya/dnsdata-go/issues/5).
- `zone`: P9 Batch 2 — `OPENPGPKEY` (RFC 7929, type 61), `CERT`
  (RFC 4398, type 37), and `URI` (RFC 7553, type 256) RR handlers.
  CERT accepts both numeric and mnemonic certificate-type codes
  (PKIX / SPKI / PGP / IPKIX / ISPKI / IPGP / ACPKIX / IACPKIX /
  URI / OID). Closes
  [#7](https://github.com/shigeya/dnsdata-go/issues/7).
- `zone`: P9 Batch 3 — `HINFO` (RFC 1035 §3.3.2, type 13) and
  `RP` (RFC 1183 §2.2, type 17) RR handlers. New
  `parseCharacterStrings` helper handles RFC 1035 §5.1 lexing and
  is reusable by future handlers. Closes
  [#8](https://github.com/shigeya/dnsdata-go/issues/8).
- `zone`: P9 Batch 4 — `EUI48` (RFC 7043 §3, type 108) and `EUI64`
  (RFC 7043 §4, type 109) RR handlers. One `EUI` struct with a
  `ByteLen` field handles both. Closes
  [#9](https://github.com/shigeya/dnsdata-go/issues/9).
- `zone`: P9 Batch 5 — `CSYNC` (RFC 7477, type 62) RR handler.
  Closes [#10](https://github.com/shigeya/dnsdata-go/issues/10).
- `zone`: P9 Batch 6 — `LOC` (RFC 1876, type 29) and `NAPTR`
  (RFC 3403, type 35) RR handlers. LOC parses
  degrees-only, degrees-minutes, and full degrees-minutes-seconds(.frac)
  forms with N/S/E/W directions; SIZE / HORIZ_PRE / VERT_PRE encode
  as mantissa<<4 | exponent centimetres. Closes
  [#11](https://github.com/shigeya/dnsdata-go/issues/11).
- `zone`: P9 Batch 7 — `SVCB` (RFC 9460, type 64) and `HTTPS`
  (RFC 9460 §9.1, type 65) RR handlers. SVCB and HTTPS share the
  identical wire and presentation format byte-for-byte; one `SVCB`
  struct backs both. Initial SvcParamKey registry covers `mandatory`,
  `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech`, `ipv6hint`,
  plus the open-ended `keyNNNNN` form for unassigned codepoints.
  Presentation order does not matter — params are sorted by key
  before encoding so wire output is always §2.2-conformant. Closes
  [#12](https://github.com/shigeya/dnsdata-go/issues/12).
- `wire`: P9 Batch 8 — `EDNS` / OPT pseudo-RR codec (RFC 6891). OPT
  lives in `wire/` rather than `zone/` because it is a meta-RR that
  appears in DNS message additional sections, never in zone files,
  and `wire.BuildQuery` already emits an OPT pseudo-RR inline.
  `wire.EDNS` exposes `Encode(b *Builder)`, `DecodeOPT(data []byte)`,
  and `FindOption(code)`, plus well-known option-code constants
  (NSID / ClientSubnet / Cookie / Padding / Chain). Defaults match
  dnsdata-js: `UDPPayloadSize=0` encodes as 4096, `DOBit=false`.
  Byte-for-byte compatible with `wire.BuildQuery`'s existing OPT
  output (verified by `TestEDNS_BuildQueryParity`). Closes
  [#13](https://github.com/shigeya/dnsdata-go/issues/13).
- `zone.RegisterHandlers()` — new opt-in entrypoint that registers
  every P9 RR handler. Parallels `dnssec.RegisterHandlers()`.

### Changed

- `wire`: `EncodeTypeBitmap` / `DecodeTypeBitmap` moved from
  `dnssec/` to `wire/` (their natural home — they encode and decode
  a wire-format bitmap of RR-type numbers). `dnssec.EncodeTypeBitmap`
  / `DecodeTypeBitmap` remain as thin delegating wrappers so existing
  callers and tests do not break; new code should reach for
  `wire.EncodeTypeBitmap` directly.

### Documentation

- README.md slimmed down; sibling-implementation model (cross-repo
  module mapping, drift policy, feature origin tagging) extracted to
  [`docs/SIBLING.md`](docs/SIBLING.md), which links to the workspace
  `DESIGN.md` as the source of truth.
- Position `dnsdata-go` and `dnsdata-js` as equal sibling
  implementations (Model C). README, DESIGN, and UPSTREAM_FEEDBACK
  reframed away from a fixed TS → Go direction; UF-NNN / UP-NNN
  remain as the Go-side catalogue of the bidirectional feedback
  channel. ([#3](https://github.com/shigeya/dnsdata-go/pull/3))
- UPSTREAM_FEEDBACK.md: UP-001 … UP-006 marked landed-upstream
  (dnsdata-js PRs #17, #19, #21, #22, #23, #24). Added UP-007
  recording the DoH port-back to dnsdata-js.

## [0.2.2] — 2026-05-18

### Fixed

- `verifier`: chain descent no longer terminates at the first non-cut
  label, so DNSSEC-signed names that live one or more labels below an
  unsigned intermediate name (typical case: `*.ad.jp`, `*.co.jp`,
  `*.ne.jp`, `*.kyoto.jp`, …) now validate as Secure instead of being
  misreported as Bogus at the closest signed ancestor. The descent
  loop previously `goto`-jumped to the leaf step on the first
  `descendNoCut` outcome, so e.g. `wide.ad.jp.` was leaf-resolved
  against `jp.`'s keys (RRSIG-over-leaf failed against the wrong
  zone). The fix is to `continue` past empty non-terminals and keep
  walking until a real zone cut is reached or `descendantZones` is
  exhausted. ([#1](https://github.com/shigeya/dnsdata-go/issues/1))

## [0.2.1] — 2026-05-18

### Fixed

- `resolver/{doh,auth}.Resolve` now surface the authority section of
  the response in addition to the answer section. The previous
  implementation intentionally dropped authority records, which silently
  disabled the v0.2.0 NSEC / NSEC3 negative-proof support: a verifier
  built on top of these resolvers could not locate the no-DS proof in
  the parent zone's response, so any unsigned name under an NSEC3-with-
  opt-out zone (e.g. an unsigned `.com` child) was misclassified as
  Bogus rather than Insecure. The additional section is still ignored
  (glue / EDNS OPT are not part of the validated rrset surface).
  Discovered while integrating dnsdata-go into mailsec-probe; verified
  against `google.com` / `amazon.com` (now Insecure) and
  `iana.org` / `cloudflare.com` / `example.com` (still Secure).

## [0.2.0] — 2026-05-17

Negative-proof support and alias / wildcard chasing. The chain
validator can now classify the full set of RFC 4033 §5 outcomes plus
the secure-negative variants, follow CNAME / DNAME redirections, and
validate wildcard-synthesised positive answers.

### Added

- `dnssec/` — NSEC / NSEC3 negative-proof primitives.
  - `CompareCanonicalNames` / `EqualCanonicalNames` (RFC 4034 §6.1
    canonical name comparator with wrap-around-safe ordering).
  - `NSEC.MatchesName` / `NSEC.CoversName` / `NSEC.ProvesNoData` /
    `NSEC.ProvesNoDS`.
  - `NSEC3.HasOptOut` / `NSEC3.CoversHash` / `NSEC3.ProvesNoData` /
    `NSEC3.ProvesNoDS`, plus `OwnerHashFromName` for decoding the
    leftmost base32hex label of an NSEC3 owner.
- `verifier/` — three new verdict-producing capabilities.
  - **Insecure-delegation classification.** `descendInto` consults
    the parent zone's NSEC / NSEC3 records when DS is absent: a
    valid proof flips the verdict to `Insecure` and records the
    proof source in the new `Result.InsecureReason` field.
    Supported proof shapes are matching NSEC, matching NSEC3, and
    covering NSEC3 with opt-out (RFC 5155 §6).
  - **Leaf NODATA / NXDOMAIN classification.** `Validate` leaf step
    consults NSEC / NSEC3 NODATA proofs (matching NSEC/NSEC3 with
    qtype absent from bitmap) and NXDOMAIN proofs (NSEC covering
    qname + wildcard-non-existence NSEC; or RFC 5155 §8.4
    three-record NSEC3 closest-encloser proof).
  - **CNAME / DNAME chasing.** `Validate` follows up to
    `MaxAliasHops` (10) CNAME or DNAME redirections, restarting the
    chain walk for each new qname. Each hop is captured as an
    `AliasStep` in `Result.Aliases`. Verdict is worst-of across
    hops. Loops are reported as Bogus with reason "alias loop
    detected"; chains longer than `MaxAliasHops` are reported as
    Bogus with reason "alias chain exceeded N hops".
  - **Wildcard-synthesised positive answers.** When a covering
    RRSIG's `Labels` field is fewer than the qname's label count,
    the validator detects wildcard synthesis (RFC 4034 §3.1.3),
    reconstructs the wildcard owner for digest computation, and
    requires a signed NSEC / NSEC3 proof that the next-closer name
    does not exist (RFC 4035 §5.3.4). On success the verdict
    stays Secure and the new `Result.Wildcard` field carries the
    reconstructed wildcard owner, closest encloser, next-closer
    name, and proof source. Missing or invalid non-existence proof
    classifies the answer Bogus.
- `dnssec.LabelCount`, `dnssec.LastNLabels` — RFC 4034 §3.1.3
  helpers used by the wildcard reconstructor (and reusable by
  callers porting the same logic to other RR types).
- `Result.Wildcard *WildcardInfo` field (JSON-omitempty).
- Two new verdicts: `VerdictSecureNoData` (JSON `"secure-nodata"`)
  and `VerdictSecureNXDomain` (JSON `"secure-nxdomain"`). The four
  existing verdict strings are unchanged.
- `Result.InsecureReason`, `Result.NegativeReason`, and
  `Result.Aliases` (all JSON-omitempty).

### Changed

- `Verdict` enum widened from 4 to 6 states (`MUST 2` and `MUST 11`
  in DESIGN.md §4 updated to match). Consumers that only match on
  the original four strings still see them; consumers that want
  fine-grained secure-negative routing can read the new dashed names.
- `Validate` refactored internally into `validateOneHop` +
  `resolveLeaf` + outer alias loop. Public signature unchanged.
  Existing callers see identical behaviour for non-aliased queries.
- `verifier/doc.go` "Out of scope" list now only retains RFC 5011
  trust-anchor rollover and the DNSKEY / DS cache.
- `dnssec.Zone.CreateDigestTarget` reads `rrsig.Labels` to decide
  whether to substitute the wildcard owner for digest header
  construction. Non-wildcard callers are unaffected because the
  reconstruction branch only fires when `Labels` is strictly less
  than the rrset owner's label count.

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

[0.3.0]: https://github.com/shigeya/dnsdata-go/releases/tag/v0.3.0
[0.2.2]: https://github.com/shigeya/dnsdata-go/releases/tag/v0.2.2
[0.2.1]: https://github.com/shigeya/dnsdata-go/releases/tag/v0.2.1
[0.2.0]: https://github.com/shigeya/dnsdata-go/releases/tag/v0.2.0
[0.1.0]: https://github.com/shigeya/dnsdata-go/releases/tag/v0.1.0
