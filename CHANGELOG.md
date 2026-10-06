# Changelog

All notable changes to dnsdata-go are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `zone.Registry`: a goroutine-safe map from RR type to handler
  factory. `zone.NewRegistry()`, `(*Registry).Register(rrtype,
  factory)` (a nil factory removes the entry) and `Lookup(rrtype)`.
  The package registry is now `zone.DefaultRegistry()`;
  `zone.RegisterRRHandler`, `zone.RegisterHandlers`,
  `dnssec.RegisterHandlers`, `ResourceRecord.Handler` and
  `ResourceRecord.WireBody` use it as before.
- `ResourceRecord.HandlerFrom(reg)` and `ResourceRecord.WireBodyWith(reg, b)`:
  the handler, and the wire body, through a given registry (nil means
  the default one). The handler cached on a record is tied to the
  registry that built it and is never returned for another registry.
- `zone.RegisterHandlersInto(reg)` and `dnssec.RegisterHandlersInto(reg)`:
  the same handler sets as `RegisterHandlers`, installed into a
  caller-owned registry.
- `dnssec.Zone.SetRegistry(reg)`, `Registry()` and `Handler(rr)`: a zone
  resolves its DNSKEY / RRSIG / DS / NSEC / NSEC3 handlers, and the
  RDATA of its digest targets, through its registry (default: the
  package one).
- `verifier.WithRegistry(reg)`: the registry a Verifier resolves
  handlers through.
- `dnssec.SigStatus` (`SigVerified`, `SigExpired`, `SigNotYetValid`,
  `SigUnsupportedAlgorithm`, `SigNoMatchingKey`, `SigInvalid`; `String()`
  gives `verified`, `expired`, `not-yet-valid`, `unsupported-algorithm`,
  `no-matching-key`, `invalid`), `Zone.CheckRRSIG` (one RRSIG: why it
  failed), `Zone.CheckRRSet` (every RRSIG over an rrset, as
  `[]dnssec.SigResult{RRSig, Status, Err}`) and `dnssec.RRSetVerified`
  (folds those into `VerifyRRSet`'s answer). `VerifyRRSIG` is now
  `CheckRRSIG` reduced to a bool; its results are unchanged.
- `verifier.Result.ReasonCode` (JSON `reasonCode`, omitted when empty):
  the machine-readable cause of a failing verdict, set on every Bogus
  and Insecure result. Codes and the sentinel `Result.Err()` wraps:
  `no-ds` → `ErrNoDS` (Insecure), `no-dnskey` → `ErrNoDNSKEY`,
  `trust-anchor-mismatch` → `ErrTrustAnchorMismatch`, `ds-mismatch` →
  `ErrDSMismatch`, `no-rrsig` / `no-matching-key` / `sig-invalid` →
  `ErrSigInvalid`, `sig-expired` / `sig-not-yet-valid` →
  `ErrSigExpired`, `unsupported-algorithm` → `ErrUnsupportedAlgo`,
  and `alias-loop`, `alias-limit`, `alias-target-invalid`,
  `wildcard-proof-missing` → `ErrBogus` only. Every Bogus `Err()` also
  wraps `ErrBogus`. Exported as `verifier.Code*` constants. When every
  signature over an rrset uses an unsupported algorithm, Validate still
  returns its `ErrVerifier` error with an Indeterminate result, which
  now carries `unsupported-algorithm`.
- `verifier.Result.Err()`: nil when `ReasonCode` is empty, otherwise an
  error wrapping the code's sentinel (and `ErrBogus` for Bogus) whose
  text carries the failure point and the human reason.
- `verifier.ErrBogus`, `ErrSigInvalid`, `ErrDSMismatch`: new sentinels,
  reached through `Result.Err()`. `ErrNoDS`, `ErrNoDNSKEY`,
  `ErrSigExpired`, `ErrUnsupportedAlgo` and `ErrTrustAnchorMismatch`,
  declared but never surfaced before, are now reached the same way.
  `Validate`'s own errors are unchanged.
- `verifier.ZoneStep.Signatures` (JSON `signatures`, omitted when
  empty): one `verifier.SigCheck` per RRSIG examined at the zone, in
  check order: the DS rrset of the descent into the zone, the DNSKEY
  rrset, then the answer / CNAME / DNAME rrsets verified there (denial
  NSEC / NSEC3 records are not listed). Every RRSIG over those rrsets is
  checked and listed, not only the first that verifies; verdicts are
  unchanged. `SigCheck` is `{name, rrType, keyTag, algorithm, signer,
  inception, expiration, result}` (times in UTC); `result` is one of
  `verifier.SigVerified` (`verified`), `SigExpired` (`expired`),
  `SigNotYetValid` (`not-yet-valid`), `SigUnsupportedAlgorithm`
  (`unsupported-algorithm`), `SigNoMatchingKey` (`no-matching-key`),
  `SigInvalid` (`invalid`), the classification of
  `dnssec.Zone.CheckRRSIG`.

### Changed

- `verifier.NewVerifier` no longer calls `dnssec.RegisterHandlers()`
  and leaves `zone.DefaultRegistry()` untouched (DESIGN.md MUST NOT 22).
  Each Verifier owns a registry: by default a fresh one with the DNSSEC
  handlers only (the set it used to register, so verdicts are
  unchanged), or the one given with `WithRegistry`. Code that relied on
  constructing a Verifier to register the DNSSEC handlers globally must
  call `dnssec.RegisterHandlers()` itself. A handler obtained with
  `ResourceRecord.Handler()` (default registry) is no longer the one a
  Verifier sees, so mutating it does not affect validation; pass
  `WithRegistry(zone.DefaultRegistry())` to share it.
- The handler cache on `zone.ResourceRecord` is now safe for concurrent
  use; a `ResourceRecord` must not be copied by value.
- A Bogus result's `Chain` now ends with a step for the zone where
  validation failed (root DNSKEY, DS or DNSKEY of the descent), with
  its DNSKEYs / DS digests as far as they were loaded, the failing
  `Signatures`, and no `SignedBy`. Before, the chain stopped at the
  last zone that validated.

### Fixed

- `verifier.ZoneStep.DSDigests` was always empty: it was read from the
  child zone, while the DS records live in the parent's response. It
  now lists the DS records that authorised the descent into the zone.

## [0.9.0] — 2026-10-05

A diagnostic command, `dnsview`, that shows query by query what the
verifier concluded against one server. The library API and its
behaviour are unchanged. Coordinated release with dnsdata-js v0.9.0.

### Added

- `cmd/dnsview`: a diagnostic command that validates queries against
  one server (UDP, TCP on truncation) and prints, per query, one JSON
  line `{"query","server","error"?,"result"}` with the
  `verifier.Result` as it marshals itself. `-server` is required;
  `-type` (comma-separated, any case), `-anchors` (default: the
  built-in IANA root anchors), `-cd`, `-timeout` (default 10s)
  (UP-020). NAME may be given in any case, with or without the
  trailing dot: the verifier normalises it, and `query.name` echoes
  it as given. DESIGN.md §4 now states that MUST NOT 20 and 24 bind
  the library packages, not the commands under `cmd/`.

## [0.8.0] — 2026-10-03

Transports and signing: a DNS-over-TLS client, the CD bit on queries,
NSEC3 signing with NSEC3 proofs from the in-memory authority (UP-016 –
UP-019). No API is removed or changed in shape, but presentation and
verdicts change: TLSA / SMIMEA / SVCB / HTTPS RDATA is presented by
type instead of `\#`, TXT and CAA use `\DDD` escapes, and alias and
negative-proof fixes (UF-007, DNAME under opt-out NSEC3) change the
verdict of DNAME answers, alias answers from recursive resolvers and
wildcard NODATA. Answers the clients received now sign as the octets
they arrived as, so TLSA / SVCB validation needs no zone handlers.
Coordinated release with dnsdata-js v0.8.0.

### Added

- `zone.NewResourceRecordWithRData`: a record with its presentation
  value and the RDATA octets it was received as. `WireBody` writes
  those octets when no handler or built-in encoder exists for the
  type. The DoH / auth / DoT clients build their records with it.
- `wire.FlagCD`, `wire.QueryOptions` and `wire.BuildQueryWithOptions`:
  a query with the CD (checking disabled) bit, RFC 4035 §3.2.2.
  `doh.WithCheckingDisabled` and `auth.WithCheckingDisabled` set it on
  every query, so a validating upstream returns data it would reject
  as bogus instead of SERVFAIL. Off by default; queries are unchanged.
- `signer.Options.NSEC3` and `signer.BuildNSEC3`: sign with an NSEC3
  chain (RFC 5155 §7.1) and an NSEC3PARAM at the apex instead of NSEC.
  `&signer.NSEC3Options{}` is the RFC 9276 profile (no extra
  iterations, no salt); `Iterations`, `Salt` and `OptOut` (unsigned
  delegations left out of the chain, RFC 5155 §6) are options. NSEC
  stays the default. BIND's `dnssec-verify` accepts both profiles.
- `resolver/memory` answers zones signed with NSEC3 with NSEC3 proofs
  (RFC 5155 §7.2): NODATA, empty non-terminal, NXDOMAIN, wildcard
  answer and wildcard NODATA, and the referral to a delegation without
  DS, by the matching NSEC3 or, under opt-out, the closest provable
  encloser proof.
- `resolver/dot`: a DNS-over-TLS client (RFC 7858) with the shape of
  the auth and DoH clients: `NewClient`, `WithServers` (port 853 by
  default), `WithTLSConfig`, `WithTimeout`, `WithCheckingDisabled`,
  `Query`, `QueryRaw`, and `Resolve` returning a `resolver.Response`.
  The server is authenticated as in RFC 8310 strict privacy (trusted
  root, matching name or address, TLS 1.2 or later). One connection
  per query.

### Changed

- `resolver/auth` writes the TCP length prefix and the query in one
  write (RFC 7766 §8), sharing the framing with `resolver/dot`. The
  auth, DoH and DoT clients share the conversion of a response into a
  `resolver.Response`; results and errors are unchanged.
- TXT character-strings and the CAA value use RFC 1035 §5.1 escapes in
  both directions. `RDataToString` writes octets that are neither
  printable ASCII nor part of valid UTF-8 as `\DDD` (control characters
  included) instead of raw; the CAA value is quoted the same way
  instead of with Go's `%q` (`\xff`, `\n`). Reading a TXT or CAA value,
  `\DDD` is one octet and `\X` is `X`, in quoted strings and bare tokens;
  previously `\065` read as `065`. A `\DDD` above 255 is an error. A
  CAA value with escaped quotes now round-trips. Shared vectors
  "TXT control and invalid UTF-8" and "CAA non-ASCII and escapes".
- `RDataToString` writes TLSA and SMIMEA as `usage selector
  matching-type hex`, and SVCB and HTTPS as `priority target
  key=value ...` (the RFC 9460 mnemonics and `keyNNNNN`, the latter
  with a hex value) instead of the generic `\# <len> <hex>`. Both read
  back through `zone.NewResourceRecord` to the same octets; RDATA that
  would not (keys out of order, an ALPN id with `,` or non-ASCII, an
  IPv4-mapped `ipv6hint`, an uppercase target, empty TLSA data) is
  still generic, as is malformed RDATA, so it is not an error. Shared
  vectors "SVCB all keys", "SVCB keys out of order" and "TLSA empty
  data".

### Fixed

- DNAME answers validate. The leaf step tried CNAME before DNAME, and
  the CNAME synthesised from a DNAME has no RRSIG (RFC 6672 §5.3.1), so
  every name below a DNAME was Bogus (UF-007).
- Alias answers from recursive resolvers validate. The leaf step
  counted records of the asked type regardless of owner, so the alias
  target's RRset in the same answer made the walker verify a qname
  RRset that was not there (UF-007).
- Wildcard NODATA and empty non-terminal NODATA are `secure-nodata`,
  no longer `secure-nxdomain`; an NSEC matching the wildcard is no
  longer taken as its denial. NSEC3 wildcard NODATA (RFC 5155 §8.7) is
  `secure-nodata` instead of `indeterminate` (UF-007).
- `AliasStep.From` of a DNAME hop is the DNAME owner, as documented,
  instead of the name queried in that hop. CNAME hops are unchanged
  (the owner is the queried name). The queried name of a hop is the
  previous hop's `Target`.
- `resolver/memory` answers aliases as real authoritative servers do:
  a wildcard CNAME is synthesised for queries of any type (RFC 4592
  §3.3.3), not only CNAME; and a DNAME answer carries the unsigned
  CNAME synthesised from it (RFC 6672 §5.3.1).
- TLSA, SMIMEA, SVCB and HTTPS answers from the DoH / auth / DoT
  clients validate without `zone.RegisterHandlers()`. Since that RDATA
  is presented by type, only the zone handlers could encode it back for
  the RRSIG check, and validation ended in an error ("no encoder"). The
  clients now keep the received octets on the record
  (`zone.NewResourceRecordWithRData`), and `WireBody` writes them when
  no handler or built-in encoder exists for the type. `NewVerifier`
  still registers only the DNSSEC handlers. A record that still has no
  encoder fails with an error naming the registration it needs. Shared
  vector `testdata/handlers` in `verifier/`, served over UDP.
- A name below a DNAME in a zone signed with opt-out NSEC3 follows the
  DNAME. The walker asked for DS at every ancestor of the query name
  and took an opt-out NSEC3 that happened to cover the name's hash
  (sent as the denial for the DNAME owner) as proof of an unsigned
  delegation, so the verdict was Insecure at the query name with no
  DNAME hop. A name below a DNAME is never a zone cut (RFC 6672 §2.4;
  RFC 6840 §4.1), so no "no DS" proof is sought for it.

## [0.7.0] — 2026-09-24

Zone signing and offline validation: unknown RR types as first class,
a strict zone reader, canonical output, a zone signer, an in-memory
authority, and the validated answer on `Result`. No API is removed or
changed in shape, but two validation fixes change verdicts: RRSIGs
outside their validity window are now Bogus (UF-006), and RRsets whose
members differ in length now verify against other signers (UF-005).
dnsdata-js port-back of UP-010..015 and UF-005/006 is pending.

### Added

- RFC 3597 unknown types (UP-010). `StringToRRType` / `StringToRRClass`
  accept `TYPE<n>` / `CLASS<n>`; new `types.RRTypeName` /
  `types.RRClassName` never fail. `zone.ParseGenericRData`,
  `zone.NewResourceRecordFromRData`, `ResourceRecord.GenericRData`,
  `ResourceRecord.TXTStrings`, and `wire.FormatGenericRData`.
- `testdata/rdata_roundtrip.json`: RDATA round-trip vectors shared with
  dnsdata-js.
- `Zone.ReadStringStrict` and `zone.ParseError` (UP-011): a master-file
  reader that rejects, with a line number, what `ReadString` skips.
- `Zone.RecordsCanonical`, `Zone.PrintCanonical` and
  `zone.CompareCanonicalNames` (UP-012): RFC 4034 §6 canonical order.
- New package `dnssec/signer` (UP-013): key generation and loading
  (PKCS#8 PEM, BIND `.private`), DS and trust-anchor derivation,
  `BuildNSEC`, and `SignZone` with a caller-supplied validity window.
- New package `resolver/memory` (UP-014): an in-memory authority for
  signed zones usable as `verifier.Resolver`, with fault injection.
  Tests, an example and `testdata/signed/` fix validation under a
  private root via `WithTrustAnchors` and `WithClock`.
- `verifier.Result.Answer` (UP-015): the validated terminal RRset with
  presentation values, RDATA octets and TTLs, and the RRSIGs that
  verified it with their validity windows. Set only for Secure; other
  results serialise as before.

### Fixed

- A value in `\# <len> <hex>` form is written verbatim by `WireBody` for
  any type. Previously TLSA / SMIMEA / SVCB / HTTPS / unknown RDATA
  received from the wire encoded to nothing, so a correctly signed RRset
  of those types validated as Bogus.
- `SignRR` signs RRsets of types without a mnemonic instead of failing.
- RRSIG digest target orders RRset members by RDATA alone and removes
  duplicates (RFC 4034 §6.3, UF-005). RRsets whose members differ in
  length now verify against signatures made by other signers.
- The verifier enforces the RRSIG validity window against its clock
  (RFC 4035 §5.3.1, UF-006). An expired or not-yet-valid signature is
  now Bogus; previously `WithClock` was accepted and ignored. New
  `dnssec.Zone.SetClock`; without it `dnssec.Zone` does not check the
  window.

## [0.6.0] — 2026-05-20

Coordinated release with dnsdata-js v0.6.0 and mailsec-probe v0.6.0.
Skips v0.5.0 in this repo (was used for the `v0.5.0-rc.1` pre-release
during UP-009 development; the rc tag remains in place for archaeology
but is not a published stable line — pin v0.6.0 instead).

### Changed (BREAKING)

- New `resolver` package introduces `type Response { Records, AD, RCode }`,
  and both `resolver/doh.Client.Resolve` and `resolver/auth.Client.Resolve`
  now return `(resolver.Response, error)` instead of
  `([]*zone.ResourceRecord, error)`. The AD bit and RCODE from the response
  header are surfaced verbatim so consumers (notably mailsec-probe's
  `dnsclient`) no longer need to re-parse the wire message to recover them.
- Non-zero RCODE is no longer reported as `ErrResolverResponse`. The
  resolver layer returns the parsed response as data; only transport-level
  failures (network, parse) come back as errors. Callers that need
  "any non-zero RCODE is fatal" should inspect `resp.RCode` themselves.
- `verifier.Resolver.Query` and `verifier.ResolverFunc` signatures updated
  in lockstep to `(ctx, name, qtype) (resolver.Response, error)`. The
  RCODE classification policy moves into `verifier/chain.go::loadRecords`:
  RCODE 0 and 3 (NXDOMAIN) are treated as "no records present" so the
  existing NODATA / NXDOMAIN proof paths handle them; any other non-zero
  RCODE joins `ErrResolver`.

Tracked as UP-009.

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
