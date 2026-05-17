# UPSTREAM_FEEDBACK.md

Items discovered while implementing dnsdata-go that **should be reflected back
into dnsdata-js (TypeScript)**. The reverse-direction (Go → TS) feedback channel
for co-design.

There are two flavours of entry:

- **UF-NNN — Feedback** items report bugs / robustness gaps / API-shape problems
  in the existing TS source that the Go port had to deviate from. Once an item
  reaches `fixed-upstream`, the corresponding Go-side deviation comment may be
  removed.
- **UP-NNN — Proposals** items describe **new functionality** the Go port
  shipped that does **not** yet exist in TS. They are roadmap notes for porting
  the new surface back, not bug reports. Status meanings are slightly different
  for proposals (see legend below).

Each item is intended to be transcribed into a dnsdata-js issue / PR /
DESIGN.md change.

## Summary — UF (feedback / fixes)

| ID | Description | TS source | Type | Status |
|---|---|---|---|---|
| [UF-001](#uf-001) | `domain_name2wire`'s `\| 0x20` lowercase corrupts the underscore byte (0x5F → 0x7F) | `dns_wire.ts:16` | bug | pending |
| [UF-002](#uf-002) | No label / name length validation | `dns_wire.ts:1-32` | robustness | pending |
| [UF-003](#uf-003) | Unknown enum inputs throw bare `RangeError`; no typed classification | `dns_type_table.ts:18,31,59,86,…` | api-shape | pending |
| [UF-004](#uf-004) | `ResourceRecord.get_wire_body` silently emits nothing when RDATA parse fails | `dns_zone.ts:175-295` | robustness | pending |

UF status legend:

- `pending` — handled on the Go side; not yet addressed upstream
- `filed` — issue / PR opened against dnsdata-js
- `fixed-upstream` — landed in dnsdata-js; Go-side deviation note can be removed

## Summary — UP (proposals / port-back)

| ID | Description | dnsdata-go source | Status |
|---|---|---|---|
| [UP-001](#up-001) | DNSSEC chain validator with pluggable Resolver, four-state Verdict, and JSON-friendly Result | `verifier/` | proposed |

UP status legend:

- `proposed` — Go ships the functionality; TS port-back not started
- `in-progress` — TS port underway (link the PR in the entry body)
- `landed-upstream` — equivalent functionality merged in dnsdata-js

---

## UF-001

### `domain_name2wire`'s `| 0x20` corrupts underscore

**TS source:** `packages/core/src/lib/dns_wire.ts:16`

```ts
bytes.push(d.charCodeAt(k) | 0x20); // lowercase
```

**Problem.** `b | 0x20` lowercases ASCII letters correctly but maps `'_'`
(0x5F = `0101 1111`) to 0x7F (DEL).

DKIM (`selector._domainkey.example.com`), DMARC (`_dmarc.example.com`), TLSA
(`_443._tcp.example.com`), MTA-STS (`_mta-sts.example.com`) and other
mail-security records rely heavily on underscore-prefixed labels. The
corruption is therefore **practically fatal** for this library's primary use
case. The spec tests don't exercise underscore, so the bug is silent.

**Go-side handling.** `wire/name.go:asciiToLower` implements proper ASCII
tolower (apply `+ 0x20` only when `'A' <= b <= 'Z'`, pass through otherwise),
matching RFC 4034 §6.2 canonical-form rules.

**Recommended TS fix:**

```ts
function ascii_to_lower(c: number): number {
    return (c >= 0x41 && c <= 0x5A) ? c + 0x20 : c;
}
// ...
bytes.push(ascii_to_lower(d.charCodeAt(k)));
```

Add a `_dmarc.example.com.` round-trip case to `tests/lib/dns_wire.spec.ts`.

**See also:** `wire/name.go`, `wire/doc.go`, `TestDomainNameToWire_Underscore`.

---

## UF-002

### Missing label / name length validation

**TS source:** `packages/core/src/lib/dns_wire.ts:1-32`

**Problem.** RFC 1035 §2.3.4 caps DNS labels at 63 octets and total name length
(including length octets) at 255 octets. `domain_name2wire` enforces neither.

- A label longer than 63 octets has only its low 8 bits written into the length
  octet, causing silent corruption. The high two bits may collide with the
  compression-pointer prefix (`0b11`), so decoders are likely to misinterpret
  the byte as a pointer.
- A name longer than 255 octets is broken once assembled into a DNS packet.

**Go-side handling.** `wire/name.go` returns `ErrLabelTooLong` for labels > 63
octets and `ErrNameTooLong` when the encoded form exceeds 255 octets.

**Recommended TS fix.** `domain_name2wire` should reject (throw) on label /
name overflow. A dedicated `class DNSWireError extends Error` is preferable to
a bare `RangeError` (and fits naturally with UF-003).

`wire2domain_name` should be symmetrically defensive: (a) reject a length
byte ≥ 64 as either a compression pointer or invalid, (b) reject input shorter
than the declared label length (truncation).

**See also:** `wire/name.go`, `TestDomainNameToWire_LabelTooLong`,
`TestDomainNameToWire_NameTooLong`, `TestWireToDomainName_Compressed`,
`TestWireToDomainName_Truncated`.

---

## UF-003

### Unknown enum inputs throw bare `RangeError`; no typed classification

**TS source:** `dns_type_table.ts:18, 31, 59, 86, 122, 135, 158, 170, 181, 275, 292, 308`

**Problem.** `OpCodeToString` / `RCodeToString` / `RRTypeToString` /
`RRClassToString` each throw a bare `RangeError` on unknown input. Callers
have to:

- distinguish "unknown opcode" from "unknown rrtype" by matching on the
  message string, and
- depend on human-readable strings such as
  `"RRTypeToString: unknown ns_type: <999>"`.

**Go-side handling.** `types/errors.go` declares sentinel errors; callers
identify them with `errors.Is(err, types.ErrUnknownRRType)`.

```go
var (
    ErrUnknownOpCode  = errors.New("unknown opcode")
    ErrUnknownRCode   = errors.New("unknown rcode")
    ErrUnknownRRType  = errors.New("unknown rr type")
    ErrUnknownRRClass = errors.New("unknown rr class")
    ErrUnknownAlgo    = errors.New("unknown dnssec algorithm")
)
```

**Recommended TS fix.** Use TypeScript `Error` subclasses so callers can
discriminate via `instanceof`:

```ts
export class UnknownOpCodeError extends RangeError {
    constructor(public readonly opcode: number) {
        super(`unknown ns_opcode: ${opcode}`);
    }
}
// ... same shape for UnknownRCodeError / UnknownRRTypeError / UnknownRRClassError
```

**See also:** `types/errors.go`, the `_Unknown` cases in `types/*_test.go`.

---

## UF-004

### `ResourceRecord.get_wire_body` silently emits nothing on malformed RDATA

**TS source:** `packages/core/src/lib/dns_zone.ts:175-295`

**Problem.** Every per-type encoder (`_wire_body_a`, `_wire_body_mx`,
`_wire_body_srv`, `_wire_body_caa`, ...) returns early via `if (!m) return`
when the presentation value fails to parse, leaving the builder unchanged.
The caller cannot tell the difference between (a) "type has no encoder",
(b) "encoder ran successfully and produced an empty RDATA", and (c)
"value was malformed and the entire record was silently dropped".

Result: a typo in zone-file presentation form (e.g. `MX foo bar` instead
of `MX 10 bar.example.`) produces a packet with a missing RR rather than
a clear error.

**Go-side handling.** `zone/rr.go` returns `ErrRDataFormat` from
`WireBody` when a built-in encoder sees a malformed value. Callers can
detect this with `errors.Is(err, zone.ErrRDataFormat)`.

**Recommended TS fix.** Have each `_wire_body_*` throw
`DNSZoneRDataFormatError` (already defined in `dns_exception.ts`!) when
its regex fails or when `parse_ipv4` / `parse_ipv6` return null. The
public `get_wire_body` should propagate the throw; alternatively change
its return type to `boolean` (success) for back-compat.

`get_wire_body` should also disambiguate "no encoder for this type" from
"encoder failed to parse". A separate `has_encoder(type)` predicate is
the easiest path.

**See also:** `zone/rr.go`, `zone/handler_test.go`
(`TestWireBody_MalformedAReturnsError`, `TestWireBody_MalformedMXReturnsError`,
`TestWireBody_UnsupportedTypeIsNoOp`).

---

## UP-001

### DNSSEC chain validator with pluggable Resolver

**Go source:** `verifier/` (`doc.go`, `verdict.go`, `result.go`, `resolver.go`,
`verifier.go`, `chain.go`, `errors.go`).

**What it adds.** A self-contained chain-of-trust walker that takes a
`(qname, qtype)` pair and produces a four-state `Verdict`
(`Secure | Insecure | Bogus | Indeterminate`) along with the raw evidence
(DS / DNSKEY / RRSIG presentation values) consumed during validation.

**Public API surface.**

```go
type Verifier struct{ /* opaque */ }

func NewVerifier(opts ...Option) (*Verifier, error)
func (v *Verifier) Validate(ctx context.Context, qname string, qtype uint16) (*Result, error)

type Option func(*Verifier)
func WithResolver(Resolver) Option              // required
func WithTrustAnchors(*dnssec.RootAnchors) Option
func WithClock(func() time.Time) Option

type Resolver interface {
    Query(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error)
}

type Verdict uint8
const (
    VerdictIndeterminate Verdict = iota
    VerdictSecure
    VerdictInsecure
    VerdictBogus
)

type Result struct {
    Verdict     Verdict
    Chain       []ZoneStep
    InsecureAt  string
    BogusAt     string
    BogusReason string
    Evidence    Evidence
}
```

**Design decisions worth carrying back to TS.**

1. **Resolver is an interface, not a concrete DoH client.** The walker is
   transport-agnostic; backends include DoH, authoritative UDP/TCP, and
   in-memory test fixtures. In TS the equivalent is an `interface Resolver`
   accepting `(name, qtype) → Promise<ResourceRecord[]>`.
2. **Four-state verdict with explicit Indeterminate.** RFC 4033 §5 names all
   four; mailsec-probe expects them as the lower-case strings
   `"secure"|"insecure"|"bogus"|"indeterminate"` (Result MarshalJSON enforces
   this).
3. **Trust anchors are caller-supplied, defaulting to the embedded built-in
   set.** No filesystem reads from the package itself — the caller opens any
   `~/.dnsdata/root-anchors.json` and hands it to `ReadAnchors` / passes the
   resulting `*RootAnchors` to `WithTrustAnchors`. Mirrors DESIGN.md MUST NOT
   23 ("no implicit filesystem writes / reads").
4. **`context.Context` propagates cancel / deadline** through every Resolver
   call. The TS port should use `AbortSignal` similarly so a single cancel
   tears down the whole chain walk.
5. **No init() side effects.** `NewVerifier` explicitly calls
   `dnssec.RegisterHandlers()` as part of construction, instead of relying on
   import-time registration. In TS, an equivalent `register_handlers()` call
   should land in the constructor (or be documented as a one-time bootstrap).
6. **Handler registration is global / package-level.** Multiple Verifiers can
   coexist because handler registration is idempotent and read-only after
   first call; per-Verifier registries are deferred (DESIGN.md §4 SHOULD #16
   captures this as a future optimisation).
7. **Evidence is presentation-form text, not parsed handlers.** Result is
   JSON-serialisable out of the box (DESIGN.md MUST 10) without writing
   custom marshallers for each handler type. TS can mirror this by storing
   strings rather than DNSKey / RRSig instances.
8. **Walker scope (v0.1.0).** Positive validation only. The following are
   deliberately deferred and tracked in `doc.go`:
   - NSEC / NSEC3 negative proofs (Insecure vs Bogus distinction at no-DS).
   - CNAME / DNAME chasing.
   - RFC 5011 trust-anchor rollover.
   - DNSKEY / DS rrset caching across calls (DESIGN.md SHOULD #13).

**TS migration notes.**

- `context.Context` ↔ `AbortSignal`. `ctx.Err()` checks become
  `signal.aborted` checks at the same yield points.
- Crypto: Node's `crypto.verify(null, msg, pub, sig)` already covers Ed25519
  and ECDSA; the RSA path needs `RSA-` prefixed hash strings (already used in
  `dnssec_rr.ts`).
- Test fixtures: the Go side builds three signed `dnssec.Zone` instances in
  memory and threads them through a mock Resolver. TS can do the same once
  `dnssec_zone.ts`'s `sign_rr` method gains a Resolver-shaped consumer.

**Status.** Ships in dnsdata-go v0.1.0 (Week 3). Awaiting an issue on
dnsdata-js to track the TS port.

---

## Procedure for new entries

When a new deviation **from existing TS behaviour** is introduced:

1. Append a new `UF-NNN` section to this file (numerically continuous).
2. Add a row to the "UF (feedback / fixes)" summary table.
3. From the Go source / test that embodies the deviation, reference the ID
   (`// UPSTREAM_FEEDBACK.md UF-NNN`).
4. As the item progresses to `filed` / `fixed-upstream`, update the table.

When **new functionality** is shipped in Go that TS should also gain:

1. Append a new `UP-NNN` section to this file (numerically continuous).
2. Add a row to the "UP (proposals / port-back)" summary table.
3. Cover, at minimum: the API surface (Go function signatures + types), the
   design decisions and why, and TS-specific migration notes (e.g. Promise vs
   context.Context, available crypto APIs, parsing layer).
4. As the TS port progresses, move the entry through `proposed → in-progress →
   landed-upstream` and link the dnsdata-js PR in the entry body.

For the opposite direction (TS → Go requirements), see `DESIGN.md §4`.
