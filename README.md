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
produced in collaboration with
[Claude Opus 4.7](https://www.anthropic.com/claude) running inside
[Claude Code](https://www.anthropic.com/claude-code).
