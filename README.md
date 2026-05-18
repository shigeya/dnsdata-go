# dnsdata-go

DNS / DNSSEC primitives in pure Go.

A low-level DNS / DNSSEC protocol library — wire-format codec, zone parser,
DNSSEC signature verification and chain validation, and a range of resource
record types. Intended for building DNS tools, validators, custom resolvers,
and protocol experiments where direct control over wire-level details
matters more than a turnkey resolver API.

Crypto is built on `crypto/...` from the Go standard library only; no
dependency on `miekg/dns`.

A sibling TypeScript implementation,
[`dnsdata-js`](https://github.com/shigeya/dnsdata-js), is maintained in
parallel — see [Sibling implementation](#sibling-implementation) below. Both
descend from `wide-cpp-lib` (C++) and share the `~/.dnsdata/` on-disk
location so root trust anchors and similar artifacts are interoperable:

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript) → dnsdata-go (Go)
```

## Status

v0.2.2 — full end-to-end DNSSEC chain validation with NSEC / NSEC3
negative-proof support, CNAME / DNAME chasing, and wildcard-synthesised
positive answer validation. Both DoH and plain UDP / TCP transports.
Pre-release: API surface may still change before v1.0. Primary
consumer is [`mailsec-probe`](https://github.com/shigeya/mailsec-probe)
Phase 3.0; co-designed with that consumer.

`Verdict` is six-state: `secure | secure-nodata | secure-nxdomain |
insecure | bogus | indeterminate`. `Result` additionally exposes
`Aliases` (CNAME / DNAME hops) and `Wildcard` (synthesis evidence)
when applicable.

Out of scope for v0.2.2 (tracked in `verifier/doc.go`): RFC 5011
trust-anchor rollover, DNSKEY / DS rrset caching.

## Layout

| Package | Purpose |
|---|---|
| `types/` | RR type / class / opcode / rcode / DNSSEC algorithm enums + string conversion |
| `wire/` | DNS wire-format codec — names (with compression), builder, message parser, per-type RDATA → presentation, query builder |
| `zone/` | zone file parser, `ResourceRecord` with pluggable RR-type handlers |
| `dnssec/` | DNSKEY / RRSIG / DS / NSEC / NSEC3 / NSEC3PARAM handlers, root trust anchors, chain operations |
| `resolver/doh/` | RFC 8484 DoH client with Google / Cloudflare / Quad9 failover |
| `resolver/auth/` | UDP / TCP plain-DNS client with TC fallback and multi-server failover |
| `verifier/` | DNSSEC chain-of-trust walker (`Validate(ctx, qname, qtype) → *Result`) |

## Quick start

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

    "github.com/shigeya/dnsdata-go/resolver/doh"
    "github.com/shigeya/dnsdata-go/types"
    "github.com/shigeya/dnsdata-go/verifier"
)

func main() {
    client := doh.NewClient()
    v, err := verifier.NewVerifier(verifier.WithResolver(verifier.ResolverFunc(client.Resolve)))
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    res, err := v.Validate(context.Background(), "example.com.", types.TypeA)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    _ = json.NewEncoder(os.Stdout).Encode(res)
}
```

## Sibling implementation

`dnsdata-go` and [`dnsdata-js`](https://github.com/shigeya/dnsdata-js) are
sibling implementations of the same library, maintained side-by-side. Both
are first-class implementations — neither is permanently "upstream":

- Either side may **originate** a new feature; the originating side is the
  reference for that feature's behaviour until both sides ship. For example,
  the wire-format codec, zone-file parser, and DNSSEC RR handlers (DNSKEY,
  RRSIG, DS, NSEC, NSEC3) originated in `dnsdata-js`; the chain validator,
  DNS message parser + RDATA presentation decoders, authoritative-DNS client,
  NSEC / NSEC3 negative-proof primitives, CNAME / DNAME chasing, and
  wildcard-synthesised positive-answer support all originated in
  `dnsdata-go` (v0.1.0 – v0.2.0).
- Bug-fix feedback flows both directions (Go ↔ TS) via each repo's
  `UPSTREAM_FEEDBACK.md`. The file name is retained for backward link
  compatibility; under the sibling model it is the cross-repo feedback
  channel, not a fixed-direction one.
- Public API surface, wire output, and presentation strings are kept
  **byte-for-byte equivalent** where the contract is defined, even where
  each language's idioms differ (e.g. `context.Context` ↔ `AbortSignal`,
  sentinel errors ↔ `instanceof` subclasses, `[]byte` ↔ `Uint8Array`,
  `CamelCase` ↔ `snake_case`).

### Cross-repo module mapping

Each TS file maps to one Go package (and vice versa) so port-backs are
mechanical:

| TS (`dnsdata-js/packages/core/src/lib/`) | Go (`dnsdata-go`) | Notes |
|---|---|---|
| `dns_wire.ts` (encode/decode)       | `wire/name.go`             | `domain_name2wire`, `wire2domain_name` |
| `dns_wire.ts` (`parse_domain_name`) | `wire/name_decompress.go`  | RFC 1035 §4.1.4 compression-pointer decoder |
| `dns_message.ts`                    | `wire/message.go`          | `parse_message`, `Header`, `Question`, `RawRR`, `RawMessage` |
| `rdata_decoder.ts`                  | `wire/rdata.go`            | `rdata_to_string`, RFC 3597 fallback |
| `dns_zone.ts`                       | `zone/rr.go`, `zone/zone.go` | `ResourceRecord`, `Zone`, handler registry |
| `dnssec_zone.ts`                    | `dnssec/zone.go`           | Chain-of-trust verification helpers, canonical digest target |
| `dnssec_rr.ts`                      | `dnssec/{dnskey,rrsig,ds,nsec,nsec3}.go` | `DNSKey`, `RRSig`, `DNSRR_DS`, `DNSRR_NSEC`, `DNSRR_NSEC3` |
| `dnssec_util.ts`                    | `dnssec/canon.go`          | Canonical-name compare + `LabelCount` / `LastNLabels` (UP-004) |
| `verifier.ts`                       | `verifier/`                | Chain-of-trust walker with pluggable `Resolver` (UP-001, UP-005, UP-006) |
| `dns_type_table.ts`                 | `types/`                   | RR-type / class / rcode / algorithm tables |
| `resolver_auth.ts`                  | `resolver/auth/`           | UDP / TCP authoritative-DNS client (UP-003) |
| `dnssec_key_loader.ts`              | `dnssec/anchors.go`        | Root trust anchors |

### Drift policy

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

### Feature origin tagging

When you propose or implement a new feature in either repo, label the
Issue / PR with the originator:

- *Originated in dnsdata-go vX.Y.Z* — first shipped on the Go side
- *Originated in dnsdata-js vX.Y.Z* — first shipped on the TS side

This makes it easy to find the reference implementation at any later point.

## License

MIT — see [LICENSE](./LICENSE).

## Acknowledgements

The design, implementation, and documentation in this repository were produced in collaboration with [Claude Opus 4.7](https://www.anthropic.com/claude) running inside [Claude Code](https://www.anthropic.com/claude-code).
