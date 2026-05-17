# dnsdata-go — Design

## 1. Overview

DNS / DNSSEC primitives and a chain-of-trust validator implemented in pure Go.

Lineage:

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript) → dnsdata-go (Go)   ← here
```

- Module path: `github.com/shigeya/dnsdata-go`
- Crypto: Go standard library only (`crypto/rsa`, `crypto/ecdsa`,
  `crypto/ed25519`, `crypto/sha256`, …).
- Dependencies: **no** external DNS library such as `miekg/dns`. RR type codes
  are passed as raw `uint16`.
- Primary consumer:
  [`mailsec-probe`](https://github.com/shigeya/mailsec-probe) Phase 3.0.

## 2. Package layout (target)

| Package | Role | TS source |
|---|---|---|
| `types/` | Enums and string conversion for RR type / class / opcode / rcode / DNSSEC algorithm | `dns_type_table.ts` |
| `wire/` | DNS wire-format codec, `Builder` | `dns_wire.ts` + `dns_wire_util.ts` |
| `zone/` | Zone-file parser, RR canonicalisation | `dns_zone.ts` |
| `dnssec/` | DNSKEY / RRSIG / DS / NSEC / NSEC3 primitives, root trust anchors | `dnssec_rr.ts`, `dnssec_zone.ts`, `root_anchors.ts` |
| `resolver/doh/` | DoH client with failover (Google / Cloudflare / Quad9) | (new) |
| `resolver/auth/` | Direct queries to authoritative name servers | (new) |
| `verifier/` | DNSSEC chain-of-trust walker | (new) |

## 3. Public API (to be finalised at Phase 3.0)

```go
// Validate performs DNSSEC chain validation for qname/qtype.
func (v *Verifier) Validate(ctx context.Context, qname string, qtype uint16) (*Result, error)

type Result struct {
    Verdict     Verdict  // Secure | Insecure | Bogus | Indeterminate
    Chain       []ZoneStep
    InsecureAt  string   // zone where DS disappeared (Insecure verdict)
    BogusAt     string   // zone where validation failed (Bogus verdict)
    BogusReason string
    Evidence    Evidence // raw DS / DNSKEY / RRSIG records
}
```

The detailed contract is in §4 (Requirements).

## 4. Requirements (mirror of mailsec-probe `DESIGN.md §16`)

The API contract that mailsec-probe (= the consumer) asks `dnsdata-go` to
honor. The same text is transcribed into the mailsec-probe DESIGN.md so it
can serve as the co-design **north star**.

When this section changes, both repos' DESIGN.md must be updated together.

### MUST

1. `Validate(ctx, qname, qtype) → (*Result, error)` is goroutine-safe
2. `Result.Verdict` is an enum of `Secure | Insecure | Bogus | Indeterminate`
3. `Result.Chain` contains each zone's DNSKEY/DS tags, algorithms, and RRSIG verification results
4. `Result.InsecureAt` / `Result.BogusAt` returns the failure point as a string
5. `Result.Evidence` carries the raw DS/DNSKEY/RRSIG data (forwarded into mailsec-probe Signals)
6. `context.Context` propagates cancel / deadline
7. The trust anchor source is caller-supplied (`WithTrustAnchors(io.Reader)` etc.)
8. DoH providers can be passed as a slice (failover order: Google / Cloudflare / Quad9)
9. There is a direct-to-authoritative-NS mode (to interoperate with mailsec-probe's `--dns-server`)
10. `Result` can be marshaled directly with `encoding/json`
11. `Verdict.String()` returns `"secure"` / `"insecure"` / `"bogus"` / `"indeterminate"`
12. Errors are sentinels usable with `errors.Is` (`ErrNoDS`, `ErrSigExpired`, `ErrUnsupportedAlgo`, `ErrChainTimeout`, ...)

### SHOULD

13. A pluggable cache layer (`WithCache(c Cache)`) so root/TLD DNSKEY can be reused across a batch run
14. Streamable verification steps (`WithStepHandler(func(StepEvent))`) for verbose logging
15. RR types accepted as `uint16` (compatible with miekg/dns)
16. Memory efficiency acceptable when validating 100 domains in parallel

### MAY (future)

17. Helper converters to `miekg/dns.RR` (ecosystem interop)
18. Aggressive negative caching with NSEC/NSEC3 (RFC 8198)
19. RFC 5011 automatic trust anchor updates

### MUST NOT

20. Call `os.Exit`
21. Produce side effects from `init()` (acquiring a logger, etc.)
22. Hold global state (multiple Verifiers must be independent)
23. Write to the filesystem by default (only touch `~/.dnsdata-go/` etc. when explicitly told to)
24. Write to stdout / stderr (the caller routes output to their logger of choice)

## 5. Porting policy

- Port one TS function to one Go function (no opportunistic redesign).
- TS `RangeError` becomes a Go `error` return value, not a `panic`.
- TS `Uint8Array` becomes `[]byte`.
- Naming follows Go conventions (`OpCodeToString` exported, short parameter
  names).
- Specs are ported to Go `t.Run` table tests with the same inputs and expected
  outputs as the source.

When you notice a TS-side bug, robustness gap, or API-shape issue during
porting, record it in [`UPSTREAM_FEEDBACK.md`](./UPSTREAM_FEEDBACK.md) with a
`UF-NNN` ID. That file is the reverse-direction (Go → TS) feedback channel and
is eventually transcribed into dnsdata-js issues / PRs.

## 6. Roadmap

Mirror of the schedule table in mailsec-probe `DESIGN.md §16`.

| Week | dnsdata-go side | mailsec-probe side |
|------|------------------|---------------------|
| Week 1 | repo bootstrap; minimal `types/`, `wire/` + tests (`zone/` slipped to Week 2) | (none) |
| Week 2 | `zone/`, full `dnssec/` (DNSKEY/RRSIG/DS/NSEC/NSEC3/anchors + chain ops), `resolver/doh/` | (none) |
| Week 3 | `verifier/chain.go` (chain walker), `resolver/auth/`, `v0.1.0` tag | implement `--dnssec-mode validate`, swap in `internal/probe/dnssec/`, regenerate goldens |

Week 1 actuals: `types/` and `wire/` shipped with tests at 100% line
coverage.

Week 2 actuals:

- `zone/` — RR base, master-file parser, RR-handler registry.
- `dnssec/` — root anchors (`AnchorDS` / `AnchorDNSKEY` + builtin
  KSK-2017 / KSK-2024); `DNSKey` with RFC 4034 Appendix B key-tag, RSA
  (PKCS#1 v1.5), ECDSA (P-256/P-384), Ed25519 sign + verify; `RRSig`
  with both YYYYMMDDhhmmss and epoch-second datetime parsing;
  `DS` + `VerifyDigest` (SHA-1 / SHA-256 / SHA-384); `NSEC` with type
  bitmap codec; `NSEC3` + `NSEC3PARAM` with base32hex decoding and
  RFC 5155 §5 hashing. `Zone` wraps `zone.Zone` with parent pointer,
  SEP set, RFC 4034 §6.2 canonical digest-target builder, and
  KSK/ZSK/CSK verification modes. Coverage 80.2%. Handler registration
  is opt-in via the exported `RegisterHandlers()` — no `init()` side
  effects per §4.21.
- `resolver/doh/` — RFC 8484 DoH client with provider failover (Google
  / Cloudflare / Quad9), EDNS(0) OPT with the DO bit, transport-only
  surface returning raw response bytes. Coverage 93.8%.

Week 3 actuals:

- `verifier/` — chain validator (`Validate(ctx, qname, qtype)`),
  four-state `Verdict`, `Result` with chain / evidence,
  `Resolver` interface for pluggable transport. Coverage 80.4%.
  Out of scope for v0.1.0 (tracked in `verifier/doc.go`): NSEC /
  NSEC3 negative proofs, CNAME / DNAME chasing, RFC 5011 trust-anchor
  rollover, DNSKEY / DS cache.
- `wire/` extensions — `BuildQuery` (shared by both transports),
  `ParseMessage` with compression-pointer-aware `ParseDomainName`,
  per-type `RDataToString` decoders for A, AAAA, NS, CNAME, PTR,
  DNAME, MX, TXT, SOA, SRV, CAA, DNSKEY, CDNSKEY, DS, CDS, RRSIG,
  NSEC, NSEC3, NSEC3PARAM (RFC 3597 §5 generic form for unknown
  types). Coverage 87.0%.
- `resolver/doh.Client.Resolve` — composes Query + ParseMessage +
  RDataToString + zone.NewResourceRecord. Plugs directly into
  `verifier.ResolverFunc(client.Resolve)`. Coverage 93.8%.
- `resolver/auth/` — UDP / TCP plain-DNS client. UDP-first with
  transparent TCP fallback on TC, multi-server fail-over,
  transaction-ID validation, configurable per-server timeout +
  context deadline. Same `Resolve` adapter shape as DoH so either
  transport drops into `verifier`. Coverage 83.5%.

UP-001 (chain validator), UP-002 (parser + RData decoders), and
UP-003 (auth resolver) document the new public surface for
dnsdata-js port-back in `UPSTREAM_FEEDBACK.md`.

Session handoff and ongoing notes live in `CLAUDE.md`.
