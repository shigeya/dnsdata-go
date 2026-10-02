# Sibling implementation

`dnsdata-go` and [`dnsdata-js`](https://github.com/shigeya/dnsdata-js) are
sibling implementations of the same library, maintained side-by-side. Both
are first-class implementations — neither is permanently "upstream":

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript) → dnsdata-go (Go)
```

Both descend from `wide-cpp-lib` (C++) and share the `~/.dnsdata/` on-disk
location so root trust anchors and similar artifacts are interoperable.

The cross-repo design contract, source-of-truth assignments, and the
overall port-back policy are described in the workspace-level
[`dnsdata-workspace` `DESIGN.md`](https://github.com/shigeya/dnsdata-workspace/blob/main/DESIGN.md).
This document captures the Go-side view of the sibling relationship.

## Origination

Either side may **originate** a new feature; the originating side is the
reference for that feature's behaviour until both sides ship. For example:

- The wire-format codec, zone-file parser, and DNSSEC RR handlers
  (DNSKEY, RRSIG, DS, NSEC, NSEC3) **originated in `dnsdata-js`**.
- The chain validator, DNS message parser + RDATA presentation decoders,
  authoritative-DNS client, NSEC / NSEC3 negative-proof primitives,
  CNAME / DNAME chasing, and wildcard-synthesised positive-answer
  support all **originated in `dnsdata-go`** (v0.1.0 – v0.2.0).
- Later Go-originated features — the DoH client, the verifier cache, the
  `resolver.Response` shape, RFC 3597 unknown types, the strict reader,
  canonical output, the zone signer, the in-memory authority and
  `Result.Answer` (UP-007 – UP-015, v0.1.0 – v0.7.0) — have all landed
  in `dnsdata-js`; see [`UPSTREAM_FEEDBACK.md`](../UPSTREAM_FEEDBACK.md).

Bug-fix feedback flows both directions (Go ↔ TS) via each repo's
[`UPSTREAM_FEEDBACK.md`](../UPSTREAM_FEEDBACK.md). The file name is
retained for backward link compatibility; under the sibling model it is
the cross-repo feedback channel, not a fixed-direction one.

Public API surface, wire output, and presentation strings are kept
**byte-for-byte equivalent** where the contract is defined, even where
each language's idioms differ (e.g. `context.Context` ↔ `AbortSignal`,
sentinel errors ↔ `instanceof` subclasses, `[]byte` ↔ `Uint8Array`,
`CamelCase` ↔ `snake_case`).

## Cross-repo module mapping

Both sides use the same package directories, so port-backs are
mechanical. TS paths are relative to `dnsdata-js/packages/core/src/`:

| TS | Go (`dnsdata-go`) | Notes |
|---|---|---|
| `types/dns_type_table.ts`, `types/algorithm.ts` | `types/`            | RR-type / class / opcode / rcode / algorithm tables, `TYPE<n>` / `CLASS<n>` (UP-010) |
| `wire/dns_wire.ts` (encode/decode)       | `wire/name.go`             | `domain_name2wire`, `wire2domain_name` |
| `wire/dns_wire.ts` (`parse_domain_name`) | `wire/name_decompress.go`  | RFC 1035 §4.1.4 compression-pointer decoder |
| `wire/dns_wire.ts` (`build_query`)       | `wire/query.go`            | Query builder with EDNS(0) / DO and optional CD (UP-016), shared by the DoH, auth and DoT clients |
| `wire/dns_wire_util.ts`                  | `wire/builder.go`          | Wire builder |
| `wire/dns_message.ts`                    | `wire/message.go`          | `parse_message`, `Header`, `Question`, `RawRR`, `RawMessage` (UP-002) |
| `wire/rdata_decoder.ts`                  | `wire/rdata.go`            | `rdata_to_string`, RFC 3597 fallback (UP-002) |
| `wire/rdata_svcb.ts`                     | `wire/rdata_svcb.go`       | TLSA / SMIMEA and SVCB / HTTPS presentation (UP-017) |
| `wire/ip_format.ts`                      | —                          | IP address strings (Go uses `net.IP.String`) |
| `zone/dns_zone.ts`                       | `zone/rr.go`, `zone/zone.go` | `ResourceRecord`, `Zone`, handler registry |
| `zone/generic.ts`                        | `zone/generic.go`          | RFC 3597 `\# <len> <hex>` generic RDATA (UP-010) |
| `zone/strict.ts`                         | `zone/strict.go`           | Strict master-file reader (UP-011) |
| `zone/canonical.ts`                      | `zone/canonical.go`        | RFC 4034 §6 canonical order (UP-012) |
| `zone/handlers.ts`                       | `zone/handlers.go`         | Opt-in handler registration |
| `zone/rr/*_rr.ts`                        | `zone/{tlsa,sshfp,openpgpkey,cert,uri,hinfo,rp,eui,csync,loc,naptr,svcb}.go` | Extended RR handlers (TLSA / SMIMEA are `dane_rr.ts`) |
| `zone/rr/opt_rr.ts`                      | `wire/edns.go`             | EDNS(0) OPT codec |
| `dnssec/dnssec_zone.ts`                  | `dnssec/zone.go`           | Chain-of-trust verification helpers, canonical digest target |
| `dnssec/{dnskey,rrsig,ds,nsec,nsec3}.ts`, `dnssec/dnssec_rr.ts` | `dnssec/{dnskey,rrsig,ds,nsec,nsec3}.go` | DNSSEC RR handlers, NSEC / NSEC3 proof primitives (UP-004) |
| `dnssec/dnssec_util.ts`                  | `dnssec/canon.go`          | Canonical-name compare + `LabelCount` / `LastNLabels` (UP-004) |
| `dnssec/crypto.ts`                       | `dnssec/crypto.go`         | Signature verification (Node `crypto` / Go `crypto/...`) |
| `dnssec/handlers.ts`                     | `dnssec/handlers.go`       | DNSSEC handler registration |
| `dnssec/dnssec_key_loader.ts`, `dnssec/root_anchors.ts` | `dnssec/anchors.go` | Root trust anchors |
| `dnssec/signer/`                         | `dnssec/signer/`           | Key generation / loading, DS, NSEC chain, zone signing (UP-013); NSEC3 chain (`nsec3.ts` ↔ `nsec3.go`, UP-018) |
| `resolver/response.ts`                   | `resolver/resolver.go`     | `Response { records, ad, rcode }` (UP-009) |
| `resolver/doh/`                          | `resolver/doh/`            | RFC 8484 DoH client with provider failover (UP-007) |
| `resolver/auth/`                         | `resolver/auth/`           | UDP / TCP authoritative-DNS client (UP-003) |
| `resolver/dot/`                          | `resolver/dot/`            | RFC 7858 DNS-over-TLS client (UP-019) |
| `resolver/stream.ts`                     | `resolver/internal/stream/` | Two-octet length framing on TCP / TLS, shared by auth and DoT (UP-019); TS also holds the Node socket reader |
| `resolver/message.ts`                    | `resolver/internal/message/` | Response message → `Response`, shared by auth, DoH and DoT (UP-019) |
| `resolver/addr.ts`                       | —                          | `host:port` handling (Go uses `net.SplitHostPort` / `JoinHostPort`) |
| `resolver/memory/`                       | `resolver/memory/`         | In-memory authority for signed zones (UP-014); NSEC3 proofs (`nsec3.ts` ↔ `nsec3.go`, UP-018) |
| `verifier/`                              | `verifier/`                | Chain-of-trust walker with pluggable `Resolver` (UP-001, UP-005, UP-006), `Cache` (UP-008), `Result.answer` (UP-015) |
| `dns_exception.ts`                       | per-package `errors.go`    | TS exception hierarchy ↔ Go sentinel errors |
| `../tests/testdata/`                     | `testdata/`                | Shared vectors (`rdata_roundtrip.json`, `signed/`); byte-identical, generated on the Go side |

## Drift policy

Drift that is **accepted** (idiomatic translation): control flow, error
mechanics (Go sentinel `var` vs TS `class extends Error`), naming case
(`CamelCase` vs `snake_case`), value-vs-exception conventions, primitive
types (`[]byte` vs `Uint8Array`), cancellation surface (`context.Context`
vs `AbortSignal`).

Drift that is **not accepted** (must be kept in sync): API surface (function
names, argument order, optionality semantics), output formats (wire bytes,
presentation strings), supported RR-type set, error category meanings,
DNSSEC verdict spellings (`"secure"` / `"secure-nodata"` /
`"secure-nxdomain"` / `"insecure"` / `"bogus"` / `"indeterminate"`).

## Feature origin tagging

When you propose or implement a new feature in either repo, label the
Issue / PR with the originator:

- *Originated in dnsdata-go vX.Y.Z* — first shipped on the Go side
- *Originated in dnsdata-js vX.Y.Z* — first shipped on the TS side

This makes it easy to find the reference implementation at any later point.
