# CLAUDE.md — dnsdata-go

Operating notes for working in this repository with Claude Code.

## Lineage

```
wide-cpp-lib (C++) → dnsdata-js (TypeScript) → dnsdata-go (Go)   ← here
```

- TypeScript source of truth: [`shigeya/dnsdata-js`](https://github.com/shigeya/dnsdata-js) — `packages/core/src/lib/`
- Primary consumer: [`shigeya/mailsec-probe`](https://github.com/shigeya/mailsec-probe) (co-designed in both directions)

## Design rules

- **Pure port.** No dependency on `miekg/dns`. Crypto comes from `crypto/...`
  in the Go standard library only.
- The public API must satisfy the MUST / SHOULD / MAY / MUST NOT clauses listed
  in `mailsec-probe/DESIGN.md §16`. Those clauses are mirrored in `DESIGN.md §4`
  of this repo as the source of truth for the contract.
- Public API shape:
  - `verifier.Validate(ctx, qname, qtype) → (*Result, error)` — chain validation
  - `resolver.{DoH, Authoritative}` — DoH and direct-to-authoritative DNS
  - `dnssec.*` — DNSKEY / RRSIG / DS / NSEC / NSEC3 primitives
  - `wire.*`, `types.*` — lower-level primitives
- No side effects from `init()`. Never call `os.Exit`. Never write to stdout
  or stderr.
- No global state. Multiple `Verifier` instances must be usable concurrently
  and independently.

## Porting workflow (recommended)

When porting a new TypeScript module to Go:

1. Read the TS source (`dnsdata-js/.../<x>.ts`) and its spec
   (`tests/lib/<x>.spec.ts`).
2. Create the equivalent Go package under `<x>/` (or extend an existing
   package).
3. Port the spec to `<x>_test.go` as a table-driven test.
4. Confirm parity with `go test ./<x>/...`.
5. Run `go vet ./...`.

Where the TS source throws `RangeError`, decide case by case whether the Go
equivalent returns an `error` or `panic`s. `RangeError` for an unknown enum
value should become a typed `error`.

If you spot a bug, robustness gap, or API-shape issue in the TS source while
porting, and you change behaviour on the Go side as a result, **record it in
`UPSTREAM_FEEDBACK.md` with a `UF-NNN` ID**. Deviation comments on the Go side
(`wire/doc.go`, etc.) should cross-reference that ID. This is the
reverse-direction (Go → TS) feedback channel.

## Work in progress

See the "Roadmap" section of `DESIGN.md`. Progress is synchronised with
`mailsec-probe` Phase 3.0 (target: mailsec-probe v0.1.0 → v0.3.0).

## Testing

- Base layer is `go test ./...`.
- DNSSEC primitives use Known-Answer Tests (KATs) under `testdata/`.
- Target ≥ 80% line coverage.

## Commits

- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, …).
- Auto-signatures such as `Co-Authored-By` are disabled globally in
  `~/.claude/settings.json`.
