# dnsdata-go

DNS / DNSSEC primitives in pure Go.

A from-scratch Go port of [`dnsdata-js`](https://github.com/shigeya/dnsdata-js)
(TypeScript), which itself descends from `wide-cpp-lib` (C++).
Crypto is built on `crypto/...` from the Go standard library only;
no dependency on `miekg/dns`.

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript) → dnsdata-go (Go)   ← this repo
```

## Status

v0.1.0 — full end-to-end DNSSEC chain validation, both DoH and plain
UDP / TCP transports. Pre-release: API surface may still change before
v1.0. Primary consumer is
[`mailsec-probe`](https://github.com/shigeya/mailsec-probe) Phase 3.0;
co-designed with that consumer.

Out of scope for v0.1.0 (tracked in `verifier/doc.go`): NSEC / NSEC3
negative proofs, CNAME / DNAME chasing, RFC 5011 trust-anchor rollover,
DNSKEY / DS rrset caching.

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

## License

MIT — see [LICENSE](./LICENSE).

## Acknowledgements

The design, implementation, and documentation in this repository were produced in collaboration with [Claude Opus 4.7](https://www.anthropic.com/claude) running inside [Claude Code](https://www.anthropic.com/claude-code).
