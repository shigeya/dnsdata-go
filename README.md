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

Pre-release. v0.x, breaking changes are expected.
Primary consumer is [`mailsec-probe`](https://github.com/shigeya/mailsec-probe)
Phase 3.0 DNSSEC chain validation; the API surface is being co-designed with
that consumer.

## Layout (target)

| Package | Purpose |
|---|---|
| `types/` | RR type / class / opcode / rcode / DNSSEC algorithm enums + string conversion |
| `wire/` | DNS wire-format encode/decode (domain name, `WireBuilder`) |
| `zone/` | zone file parser, RR canonicalisation |
| `dnssec/` | DNSKEY / RRSIG / DS / NSEC / NSEC3 primitives, root trust anchors |
| `resolver/` | DoH and authoritative DNS clients |
| `verifier/` | DNSSEC chain-of-trust walker (`Validate(ctx, qname, qtype) → *Result`) |

## License

MIT — see [LICENSE](./LICENSE).
