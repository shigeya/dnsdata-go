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
| [UP-002](#up-002) | DNS message wire-format parser + RDATA-to-presentation decoders, kept in `wire/` so packages stay acyclic | `wire/message.go`, `wire/rdata.go`, `wire/name_decompress.go` | proposed |
| [UP-003](#up-003) | UDP+TCP authoritative-DNS client with TC-flag fallback and multi-server failover, sharing the EDNS / DO query builder with the DoH client | `resolver/auth/` | proposed |

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

## UP-002

### DNS message wire-format parser + RDATA presentation decoders

**Go source:** `wire/name_decompress.go`, `wire/message.go`, `wire/rdata.go`.
Tests: `wire/name_decompress_test.go`, `wire/message_test.go`,
`wire/rdata_coverage_test.go`.

**What it adds.** A low-level decoder that turns DNS response bytes into a
structured [RawMessage] (header + question + answer/authority/additional
sections of RawRR), plus an `RDataToString` that converts the wire-form RDATA
of any of the common types back into the same presentation text that
`zone.NewResourceRecord` and the DNSSEC handlers consume. Together they
unblock real-network use of the chain validator (UP-001): the DoH client's
new `Client.Resolve` method composes ParseMessage + RDataToString to produce
`[]*zone.ResourceRecord` directly.

**Public API surface.**

```go
// Names with compression pointers (RFC 1035 §4.1.4).
func ParseDomainName(msg []byte, offset int) (string, int, error)

// Header + Question + RawRR per section.
type Header struct {
    ID, Flags, QDCount, ANCount, NSCount, ARCount uint16
}
func (h Header) QR() bool
func (h Header) AA() bool
func (h Header) TC() bool
func (h Header) RD() bool
func (h Header) RA() bool
func (h Header) AD() bool
func (h Header) CD() bool
func (h Header) RCode() uint8

type Question struct{ Name string; Type, Class uint16 }
type RawRR struct{ Name string; Type, Class uint16; TTL uint32; RData []byte; RDataStart int }
type RawMessage struct{ Raw []byte; Header Header; Question Question; Answer, Authority, Additional []RawRR }

func ParseMessage(msg []byte) (*RawMessage, error)

// Per-type RDATA decoder. Unknown types render in RFC 3597 §5 form.
func RDataToString(msg []byte, rrtype uint16, rdata []byte, rdataStart int) (string, error)
```

Types handled by `RDataToString`: A, AAAA, NS, CNAME, PTR, DNAME, MX, TXT,
SOA, SRV, CAA, DNSKEY, CDNSKEY, DS, CDS, RRSIG, NSEC, NSEC3, NSEC3PARAM.

**Design decisions worth carrying back to TS.**

1. **Decoder lives in `wire/`, with no dependency on `zone` / `dnssec`.**
   This keeps the package graph acyclic: wire is the lowest layer, zone and
   dnssec sit above it, and any "parse message → ResourceRecord" adapter
   lives in a caller package (in Go: `resolver/doh.Client.Resolve`). In TS
   the equivalent is to put the decoder in `dns_wire.ts` siblings rather
   than inside `dns_zone.ts`.
2. **Presentation text is the bridge.** RDATA decoders emit the same text
   the zone-file format would use. That keeps the parser independent of the
   handler registry: callers can re-parse with their existing
   `ResourceRecord` machinery. The alternative (parser-knows-handlers)
   couples wire to dnssec.
3. **Names embedded in RDATA can be compressed.** `RDataToString` takes the
   full message bytes plus `rdataStart` precisely so MX exchange, SOA
   mname / rname, NS, RRSIG signer, and friends can follow pointers that
   point outside the RDATA region. In TS the equivalent constraint is to
   pass the whole `Uint8Array` and the absolute offset to the field decoder.
4. **Compression-pointer safety in `ParseDomainName`.** Pointers must
   strictly point earlier in the message (RFC 1035 §4.1.4), label-length
   bytes ≥ 64 are rejected (the reserved 0x40 / 0x80 prefixes), and a hop
   cap aborts pathological inputs. Hops are also tracked through a `visited`
   set as belt-and-braces.
5. **Unknown types use RFC 3597 §5 generic form.** `\# <rdlen> <hex>`.
   Lets the decoder degrade safely for types the table doesn't know.
6. **`RDataStart` on every `RawRR`.** Carrying the offset on the struct (in
   addition to the byte slice) means callers don't need slice arithmetic to
   recover where the RDATA lives. In TS the same role can be filled by an
   `rdataOffset: number` field on the parsed RR.
7. **`Client.Resolve` glue.** The DoH client gains a `Resolve(ctx, name,
   qtype) → ([]*zone.ResourceRecord, error)` method that wraps `Query +
   ParseMessage + RDataToString + zone.NewResourceRecord`. The Go
   verifier.Resolver interface is satisfied via
   `verifier.ResolverFunc(client.Resolve)` — no separate adapter type
   needed.

**TS migration notes.**

- `Uint8Array` slices are reference views over an `ArrayBuffer`; record both
  the slice and its offset explicitly (TS has no `unsafe.Pointer` to recover
  it). The `RawRR` shape with `rdataOffset` is a natural fit.
- Base32hex encode is included locally in `wire/rdata.go` because importing
  `dnssec` from wire would cycle. TS does not have the same cycle constraint
  (modules can be more freely organised), but factoring base32hex into its
  own utility avoids re-implementing it in multiple places.
- Decompression: the pointer chase is iterative with cycle detection. A
  recursive implementation in TS would also need the same hop cap; pick 32
  to match.

**Status.** Ships in dnsdata-go v0.1.0 (Week 3). Awaiting an issue on
dnsdata-js to track the TS port.

---

## UP-003

### UDP / TCP authoritative-DNS client

**Go source:** `resolver/auth/` (`doc.go`, `errors.go`, `client.go`,
`resolve.go`). Tests in `client_test.go`. Builds on `wire.BuildQuery` /
`wire.ParseMessage` / `wire.RDataToString` shared with `resolver/doh`.

**What it adds.** A plain-DNS (RFC 1035) client for use against
authoritative name servers, recursive resolvers, or a local stub.
Mirrors `resolver/doh` in shape (Client + Options + Resolve method
satisfying `verifier.Resolver`), differing only in transport.

**Public API surface.**

```go
type Client struct{ /* opaque */ }

func NewClient(opts ...Option) *Client
func (c *Client) Query(ctx context.Context, qname string, qtype uint16) ([]byte, error)
func (c *Client) QueryRaw(ctx context.Context, queryID uint16, query []byte) ([]byte, error)
func (c *Client) Resolve(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error)
func (c *Client) Servers() []string

type Option func(*Client)
func WithServers(addrs ...string) Option
func WithTimeout(d time.Duration) Option
func WithUDPBufferSize(n int) Option
func WithDialer(d net.Dialer) Option

func NormalizeAddr(addr string) string
```

**Design decisions worth carrying back to TS.**

1. **UDP first, TCP on truncation.** When the UDP response has the TC
   flag set (RFC 1035 §4.2.1) the client replays the same query over
   TCP transparently. The 2-byte big-endian length prefix on the wire
   (RFC 1035 §4.2.2) is handled here. TS does this via the `dgram`
   and `net` modules; the framing logic ports straight across.
2. **Caller supplies the server list — no `/etc/resolv.conf` reads.**
   `auth.WithServers("1.1.1.1:53", "8.8.8.8:53")` is the only way to
   point the client. `NormalizeAddr` appends the default :53 port
   when missing. Per DESIGN.md MUST 9 this is a hard requirement so
   mailsec-probe's `--dns-server <ip>` round-trips cleanly without
   accidental fall-back to the system resolver.
3. **Shared query builder.** `wire.BuildQuery` / `BuildQueryWithID`
   construct the EDNS(0) / DO-bit query message; both `doh.Client`
   and `auth.Client` call it. In TS the equivalent factoring is to
   keep the query builder in `dns_wire.ts` next to the wire codec.
4. **Per-server fail-over with `errors.Join`.** Same approach as DoH:
   `ErrAllServersFailed` is joined with the first inner error so
   `errors.Is` against the inner sentinel still resolves.
5. **Transaction-ID validation.** The response's ID is compared with
   the query's; mismatches return `ErrIDMismatch`. This is a thin
   safety net against trivial off-path responses on shared UDP
   sockets — useful when the caller passes the same `Client` to
   multiple goroutines (each goroutine still gets its own random ID
   via `RandomQueryID`).
6. **`Dialer` injection for tests.** `WithDialer` lets tests swap in
   a controlled `net.Dialer`; the production default uses
   `net.Dialer{}`. TS can structure the same way with a small
   `Dialer` interface and a default implementation backed by the
   stdlib `dgram` / `net` modules.
7. **Method value satisfies `verifier.Resolver`.** Just like the DoH
   adapter, the wiring is `verifier.ResolverFunc(c.Resolve)`. No
   shim package is needed.
8. **Per-server timeout vs per-call deadline.** `WithTimeout` is the
   per-server budget; the caller's `context.Deadline` shrinks the
   effective budget if it's tighter. This keeps the failover loop
   responsive without forcing every caller to set a context deadline.

**TS migration notes.**

- Node's `dgram.createSocket('udp4')` and `net.createConnection()` map
  to the Go `net.Dialer.DialContext("udp" / "tcp", addr)` calls.
- TCP length-prefix framing is identical (2-byte big-endian); reuse
  the same `Buffer` slice arithmetic that DoH callers already use.
- `AbortSignal` propagates the cancel just like `ctx` does in Go;
  hook it into `socket.close()` on UDP and `connection.destroy()` on
  TCP for the deadline path.

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
