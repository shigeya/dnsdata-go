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
parallel — see [`docs/SIBLING.md`](docs/SIBLING.md). Both descend from
`wide-cpp-lib` (C++) and share the `~/.dnsdata/` on-disk location.

## Status

v0.8.0 — full end-to-end DNSSEC chain validation with NSEC / NSEC3
negative-proof support, CNAME / DNAME chasing, and wildcard-synthesised
positive answer validation. DoH, DNS-over-TLS and plain UDP / TCP
transports.
The default DoH provider order is **Cloudflare → Google → Quad9**
(see `resolver/doh` package doc for the rationale). Pre-release: API
surface may still change before v1.0. Primary consumer is
[`mailsec-probe`](https://github.com/shigeya/mailsec-probe) Phase 3.0;
co-designed with that consumer. See [`CHANGELOG.md`](CHANGELOG.md) for
per-release detail.

- **Validation.** `Verdict` is six-state: `secure | secure-nodata |
  secure-nxdomain | insecure | bogus | indeterminate`. `Result`
  additionally exposes `Aliases` (CNAME / DNAME hops), `Wildcard`
  (synthesis evidence) and, for Secure results, `Answer` (the validated
  RRset and the RRSIGs that verified it). RRSIG validity windows are
  enforced against the verifier's clock (`WithClock`).
- **Resolvers.** `resolver/doh` and `resolver/auth` return
  `resolver.Response{Records, AD, RCode}`. An optional `Cache`
  (`WithCache`, built-in `MemoryCache`) lets a batch run reuse root and
  TLD DNSKEY / DS rrsets.
- **Zones.** Master-file reader (lenient `ReadString` and strict
  `ReadStringStrict`), RFC 4034 §6 canonical output, RFC 3597 unknown
  types (`TYPE<n>`, `\# <len> <hex>`), and the extended RR handler set
  (TLSA, SMIMEA, SSHFP, OPENPGPKEY, CERT, URI, HINFO, RP, EUI48, EUI64,
  CSYNC, LOC, NAPTR, SVCB, HTTPS) plus an EDNS(0) OPT codec, reachable
  through the opt-in `zone.RegisterHandlers()` entrypoint.
- **Signing and offline validation.** `dnssec/signer` generates and
  loads keys, derives DS / trust anchors, builds the NSEC chain and
  signs a zone; `resolver/memory` serves signed zones as a
  `verifier.Resolver`, so a private root can be validated without the
  network.

Out of scope (tracked in `verifier/doc.go`): RFC 5011 trust-anchor
rollover.

## Layout

| Package | Purpose |
|---|---|
| `types/` | RR type / class / opcode / rcode / DNSSEC algorithm enums + string conversion |
| `wire/` | DNS wire-format codec — names (with compression), builder, message parser, per-type RDATA → presentation, query builder |
| `zone/` | zone file parser (lenient and strict), canonical output, `ResourceRecord` with pluggable RR-type handlers, RFC 3597 generic RDATA |
| `dnssec/` | DNSKEY / RRSIG / DS / NSEC / NSEC3 / NSEC3PARAM handlers, root trust anchors, chain operations |
| `dnssec/signer/` | key generation and loading, DS / trust-anchor derivation, NSEC chain, zone signing |
| `resolver/` | `Response{Records, AD, RCode}` shared by the clients below |
| `resolver/doh/` | RFC 8484 DoH client with Cloudflare / Google / Quad9 sequential failover |
| `resolver/auth/` | UDP / TCP plain-DNS client with TC fallback and multi-server failover |
| `resolver/memory/` | in-memory authority for signed zones, usable as `verifier.Resolver`, with fault injection |
| `verifier/` | DNSSEC chain-of-trust walker (`Validate(ctx, qname, qtype) → *Result`), optional `Cache` |

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

## Documentation

- [`DESIGN.md`](DESIGN.md) — API contract (mirrors mailsec-probe
  `DESIGN.md §16`), package responsibilities, roadmap.
- [`docs/SIBLING.md`](docs/SIBLING.md) — sibling-implementation model,
  cross-repo module mapping, drift policy.
- [`UPSTREAM_FEEDBACK.md`](UPSTREAM_FEEDBACK.md) — `UF-NNN` / `UP-NNN`
  cross-repo feedback log.
- [`CLAUDE.md`](CLAUDE.md) — operating notes for Claude Code.

## License

MIT — see [LICENSE](./LICENSE).

## Acknowledgements

The design, implementation, and documentation in this repository were
produced in collaboration with [Claude](https://www.anthropic.com/claude)
models (Claude Opus 4.6, 4.7, 4.8, 5 and 5.5, and Claude Fable 5) running
inside [Claude Code](https://www.anthropic.com/claude-code).
