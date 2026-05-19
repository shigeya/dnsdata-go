# UPSTREAM_FEEDBACK.md

The Go-side catalogue of the Go ↔ TS feedback channel for the
[`dnsdata-go`](https://github.com/shigeya/dnsdata-go) ↔
[`dnsdata-js`](https://github.com/shigeya/dnsdata-js) sibling
implementations. See the
[Sibling implementation](./README.md#sibling-implementation) section of
README.md for the underlying model: both repos are first-class, neither is
permanently "upstream", and either side may originate a new feature or
surface a bug fix.

The file name is retained for backward link compatibility (existing
`UF-NNN` / `UP-NNN` references in commit messages, tests, and code
comments). Under the sibling model, the word "upstream" in `fixed-upstream`
simply means "the repo on the other side of this channel" — `dnsdata-js`
from here, `dnsdata-go` from there.

This file lists items observed from the **Go side** that should land in
**TS**. Items observed in the opposite direction (TS → Go) are filed as
issues directly on the dnsdata-go repo until a mirror catalogue exists in
dnsdata-js.

There are two flavours of entry:

- **UF-NNN — Feedback** items report bugs / robustness gaps / API-shape problems
  in the existing TS source that the Go side does not share. Once an item
  reaches `fixed-upstream`, the corresponding Go-side deviation comment may be
  removed.
- **UP-NNN — Proposals** items describe **new functionality** that originated
  in `dnsdata-go` and does **not** yet exist in TS. They are roadmap notes for
  porting the new surface back, not bug reports. Status meanings are slightly
  different for proposals (see legend below).

Each item is intended to be transcribed into a dnsdata-js issue / PR /
DESIGN.md change.

## Summary — UF (feedback / fixes)

| ID | Description | TS source | Type | Status |
|---|---|---|---|---|
| [UF-001](#uf-001) | `domain_name2wire`'s `\| 0x20` lowercase corrupts the underscore byte (0x5F → 0x7F) | `dns_wire.ts:16` | bug | [fixed-upstream (#11)](https://github.com/shigeya/dnsdata-js/pull/11) |
| [UF-002](#uf-002) | No label / name length validation | `dns_wire.ts:1-32` | robustness | [fixed-upstream (#14)](https://github.com/shigeya/dnsdata-js/pull/14) |
| [UF-003](#uf-003) | Unknown enum inputs throw bare `RangeError`; no typed classification | `dns_type_table.ts:18,31,59,86,…` | api-shape | [fixed-upstream (#16)](https://github.com/shigeya/dnsdata-js/pull/16) |
| [UF-004](#uf-004) | `ResourceRecord.get_wire_body` silently emits nothing when RDATA parse fails | `dns_zone.ts:175-295` | robustness | [fixed-upstream (#15)](https://github.com/shigeya/dnsdata-js/pull/15) |

UF status legend:

- `pending` — handled on the Go side; not yet addressed upstream
- `filed` — issue / PR opened against dnsdata-js
- `fixed-upstream` — landed in dnsdata-js; Go-side deviation note can be removed

## Summary — UP (proposals / port-back)

| ID | Description | dnsdata-go source | Status |
|---|---|---|---|
| [UP-001](#up-001) | DNSSEC chain validator with pluggable Resolver, four-state Verdict, and JSON-friendly Result | `verifier/` | [landed-upstream (#17)](https://github.com/shigeya/dnsdata-js/pull/17) |
| [UP-002](#up-002) | DNS message wire-format parser + RDATA-to-presentation decoders, kept in `wire/` so packages stay acyclic | `wire/message.go`, `wire/rdata.go`, `wire/name_decompress.go` | [landed-upstream (#19)](https://github.com/shigeya/dnsdata-js/pull/19) |
| [UP-003](#up-003) | UDP+TCP authoritative-DNS client with TC-flag fallback and multi-server failover, sharing the EDNS / DO query builder with the DoH client | `resolver/auth/` | [landed-upstream (#21)](https://github.com/shigeya/dnsdata-js/pull/21) |
| [UP-004](#up-004) | NSEC / NSEC3 negative-proof primitives + Insecure-delegation + leaf NODATA / NXDOMAIN classification, six-state Verdict | `dnssec/canon.go`, `dnssec/nsec.go`, `dnssec/nsec3.go`, `verifier/negative.go`, `verifier/leaf_negative.go`, `verifier/verdict.go` | [landed-upstream (#22)](https://github.com/shigeya/dnsdata-js/pull/22) |
| [UP-005](#up-005) | CNAME / DNAME chasing with worst-of verdict combination, alias-loop detection, MaxAliasHops cap, AliasStep records | `verifier/alias.go`, `verifier/chain.go::Validate`, `verifier/result.go::AliasStep` | [landed-upstream (#23)](https://github.com/shigeya/dnsdata-js/pull/23) |
| [UP-006](#up-006) | Wildcard-synthesised positive answer support: digest target reconstruction (RFC 4035 §5.3.2) + next-closer non-existence proof (§5.3.4), `Result.Wildcard` evidence field | `dnssec/canon.go`, `dnssec/zone.go::CreateDigestTarget`, `verifier/wildcard.go`, `verifier/result.go::WildcardInfo` | [landed-upstream (#24)](https://github.com/shigeya/dnsdata-js/pull/24) |
| [UP-007](#up-007) | DoH (RFC 8484) client with provider failover, EDNS(0)/DO query builder shared with `resolver/auth`, raw-bytes Query plus parsing Resolve; replaces TS's legacy Google JSON-API client | `resolver/doh/` | in-progress |
| [UP-008](#up-008) | Pluggable `Cache` interface + built-in `MemoryCache` consulted before every `Resolver.Query`; lets a batch run reuse root/TLD DNSKEY/DS rrsets (DESIGN.md §4 SHOULD #13) | `verifier/cache.go`, `verifier/verifier.go::WithCache`, `verifier/chain.go::loadRecords` | [landed-upstream (#25)](https://github.com/shigeya/dnsdata-js/pull/25) |

UP status legend:

- `proposed` — Go ships the functionality; TS port-back not started
- `filed` — issue opened against dnsdata-js to track the TS port
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

**Tracking:** fixed in [shigeya/dnsdata-js#11](https://github.com/shigeya/dnsdata-js/pull/11) (closes [#1](https://github.com/shigeya/dnsdata-js/issues/1)).

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

**Tracking:** fixed in [shigeya/dnsdata-js#14](https://github.com/shigeya/dnsdata-js/pull/14) (closes [#2](https://github.com/shigeya/dnsdata-js/issues/2)).

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

**Tracking:** fixed in [shigeya/dnsdata-js#16](https://github.com/shigeya/dnsdata-js/pull/16) (closes [#3](https://github.com/shigeya/dnsdata-js/issues/3)).

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

**Tracking:** fixed in [shigeya/dnsdata-js#15](https://github.com/shigeya/dnsdata-js/pull/15) (closes [#4](https://github.com/shigeya/dnsdata-js/issues/4)).

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
9. **Descent must continue past empty non-terminals.** The descent
   loop walks `descendantZones(qname)` (e.g.
   `["jp.", "ad.jp.", "wide.ad.jp."]` for `wide.ad.jp.`). When a
   parent returns no DS records for a child label AND no NSEC/NSEC3
   proof of no-DS, the child is not a zone cut and the loop MUST keep
   iterating to the next deeper descendant — it MUST NOT bail out to
   leaf resolution, because a deeper label may still be a real cut.
   See **post-fix gotcha** below: the Go implementation initially
   short-circuited here, which misclassified every `*.ad.jp` / `*.co.jp`
   / `*.ne.jp` name as Bogus. Fixed in dnsdata-go
   [#1](https://github.com/shigeya/dnsdata-go/issues/1). TS port-back
   must arrive with the same behaviour from day one; add chain-walk
   tests for at least one multi-label TLD case (e.g. signed
   `wide.ad.jp.` under empty-non-terminal `ad.jp.`).

**TS migration notes.**

- `context.Context` ↔ `AbortSignal`. `ctx.Err()` checks become
  `signal.aborted` checks at the same yield points.
- Crypto: Node's `crypto.verify(null, msg, pub, sig)` already covers Ed25519
  and ECDSA; the RSA path needs `RSA-` prefixed hash strings (already used in
  `dnssec_rr.ts`).
- Test fixtures: the Go side builds three signed `dnssec.Zone` instances in
  memory and threads them through a mock Resolver. TS can do the same once
  `dnssec_zone.ts`'s `sign_rr` method gains a Resolver-shaped consumer.

**Status.** Ships in dnsdata-go v0.1.0 (Week 3). Landed in dnsdata-js
[#17](https://github.com/shigeya/dnsdata-js/pull/17) as
`packages/core/src/lib/verifier.ts` + `tests/lib/verifier.spec.ts`.

**Tracking:** landed-upstream — issue [shigeya/dnsdata-js#5](https://github.com/shigeya/dnsdata-js/issues/5), PR [#17](https://github.com/shigeya/dnsdata-js/pull/17).

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

**Status.** Ships in dnsdata-go v0.1.0 (Week 3). Landed in dnsdata-js
[#19](https://github.com/shigeya/dnsdata-js/pull/19) as
`packages/core/src/lib/dns_message.ts` +
`packages/core/src/lib/rdata_decoder.ts` (with paired spec files).

**Tracking:** landed-upstream — issue [shigeya/dnsdata-js#6](https://github.com/shigeya/dnsdata-js/issues/6), PR [#19](https://github.com/shigeya/dnsdata-js/pull/19).

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

**Status.** Ships in dnsdata-go v0.1.0 (Week 3). Landed in dnsdata-js
[#21](https://github.com/shigeya/dnsdata-js/pull/21) as
`packages/core/src/lib/resolver_auth.ts` (with paired spec file).

**Tracking:** landed-upstream — issue [shigeya/dnsdata-js#7](https://github.com/shigeya/dnsdata-js/issues/7), PR [#21](https://github.com/shigeya/dnsdata-js/pull/21).

---

## UP-004

NSEC / NSEC3 negative-proof primitives, plus the verifier-side wiring
that lifts no-DS-at-delegation, NODATA-at-leaf, and NXDOMAIN-at-leaf
responses from "no rrset present" silence into concrete verdicts with
labelled reasons. Includes a six-state Verdict enum so the two
secure-negative outcomes are distinguishable from "couldn't classify".

**Go source.** `dnssec/canon.go`, `dnssec/nsec.go` (CoversName /
MatchesName / ProvesNoData / ProvesNoDS), `dnssec/nsec3.go`
(CoversHash / HasOptOut / ProvesNoData / ProvesNoDS /
OwnerHashFromName), `verifier/negative.go`,
`verifier/leaf_negative.go`, `verifier/chain.go::descendInto` and
leaf step, `verifier/verdict.go`, `verifier/result.go::InsecureReason`
and `NegativeReason`.

**Public API.**

```go
// dnssec/canon.go
func CompareCanonicalNames(a, b string) int    // RFC 4034 §6.1
func EqualCanonicalNames(a, b string) bool

// dnssec/nsec.go
func (n *NSEC) MatchesName(owner, qname string) bool
func (n *NSEC) CoversName(owner, qname string) bool      // strict (open) range
func (n *NSEC) ProvesNoData(qtype uint16) bool           // !qtype && !CNAME
func (n *NSEC) ProvesNoDS() bool                          // NS && !DS && !SOA

// dnssec/nsec3.go
func (n *NSEC3) HasOptOut() bool
func (n *NSEC3) CoversHash(ownerHash, target []byte) bool
func (n *NSEC3) ProvesNoData(qtype uint16) bool
func (n *NSEC3) ProvesNoDS() bool
func OwnerHashFromName(owner string) ([]byte, error)

// verifier/verdict.go
const (
    VerdictIndeterminate Verdict = iota
    VerdictSecure
    VerdictSecureNoData      // new in v0.2.0
    VerdictSecureNXDomain    // new in v0.2.0
    VerdictInsecure
    VerdictBogus
)

// verifier/result.go
type Result struct {
    // ... existing fields ...
    InsecureReason string `json:"insecureReason,omitempty"`
    NegativeReason string `json:"negativeReason,omitempty"`
}
```

**Design decisions.**

1. **Primitive split, not a single big proof function.** The dnssec
   package exports only the small "does this NSEC/NSEC3 cover / match /
   look like no-DS" questions. The verifier composes them into a proof
   in `verifier/negative.go::proveNoDS`. This keeps `dnssec/` free of
   any chain-walker semantics, and lets future no-DATA / NXDOMAIN
   proof helpers reuse the same primitives.
2. **Canonical order treats trailing dot as decoration.** RFC 4034
   §6.1 leaves the choice of FQDN representation to implementations.
   We strip a trailing `.` before splitting on `.`, so `"com"` and
   `"com."` compare equal and the root sorts strictly lowest.
3. **Wrap-around NSEC / NSEC3.** Both `NSEC.CoversName` and
   `NSEC3.CoversHash` recognise the zone-trailing record (where
   next <= owner) and accept "either greater than owner OR less than
   next" as a valid cover. Tests pin this behaviour against both the
   normal and wrap cases.
4. **Bitmap "no-DS shape" requires NS and forbids both DS and SOA.**
   Forbidding SOA distinguishes a delegation point from a zone apex
   NSEC. Forbidding DS is the literal proof statement. Requiring NS
   guards against accidentally accepting an NSEC at a name the parent
   never delegated.
5. **Opt-out NSEC3 is honoured.** `proveNoDSWithNSEC3` first searches
   for a matching NSEC3 (owner-hash == H(childName)); if none, it
   re-walks looking for an NSEC3 that has the opt-out flag *and*
   covers H(childName). This makes proof discovery cheap in the
   common case while still supporting RFC 5155 §6 opt-out chains.
6. **Each candidate proof is signature-verified.** A bogus parent
   could otherwise insert an unsigned NSEC and lie about the bitmap.
   `parent.VerifyRRSet(owner, NSEC|NSEC3, KeyModeNone, "")` runs once
   per accepted candidate; if it fails the candidate is skipped, not
   reported as an error, so the chain walker falls through to its
   pre-existing "no proof" behaviour.
7. **`proveNoDS` returns (bool, string), never an error.** A failed
   proof is a classification outcome, not a runtime failure: the
   verifier's job is to *try* to prove no-DS and quietly give up if
   it can't. The string carries the proof source for `InsecureReason`.
8. **Chain walker stays backwards-compatible.** When proof is absent,
   `descendInto` keeps returning `descendNoCut` — so existing callers
   that ask for DS at a name that isn't a zone cut (most importantly
   qname itself in `Validate`) still proceed correctly to the leaf
   resolution step.
9. **Leaf step distinguishes secure-negative from indeterminate.**
   When the leaf rrset is empty, `Validate` tries `proveNoData` first
   (matching NSEC/NSEC3 with qtype missing from the bitmap), then
   `proveNXDomain`. A successful proof produces a real positive
   classification — `VerdictSecureNoData` or `VerdictSecureNXDomain`
   — instead of conflating it with "we couldn't tell".
10. **NSEC3 NXDOMAIN does the full three-record proof.** RFC 5155 §8.4
    requires a closest-encloser match, a next-closer cover, and a
    wildcard cover. The implementation walks qname's ancestors from
    longest to shortest to find the CE, then re-uses
    `findCoveringNSEC3` for NC and the wildcard. Skipping any of the
    three short-circuits to "no proof".
11. **NXDOMAIN proofs require wildcard non-existence.** Without it, a
    zone with a wildcard could lie by suppressing the wildcard answer
    and serving NSECs that only cover qname. NSEC NXDOMAIN therefore
    needs both a qname-covering NSEC and an NSEC denying
    `*.<closest-encloser>`.
12. **Six-state Verdict is additive, not breaking.** The original four
    strings (`secure`, `insecure`, `bogus`, `indeterminate`) keep their
    exact spelling. The new states use dash-separated names so old
    consumers either route them through their default case or upgrade
    to switch on the new strings explicitly.

**TS migration notes.**

- TS already has `NSEC` and `NSEC3` types in `dnssec_rr.ts` with
  `covers_type` predicates. The new methods translate cleanly into
  member functions; canonical-name compare belongs in
  `dnssec_util.ts` or alongside the bitmap helpers.
- TS lacks a chain validator today (UP-001), so `proveNoDS` will land
  there at the same time. Until then the dnssec/ primitives can ship
  independently and be unit-tested with the same fixtures.
- Base32hex decoding already exists for the NSEC3 next-hashed-owner
  field; `ownerHashFromName` reuses the same routine on the leftmost
  label.
- `bytes.Compare` on hashes maps to a `Uint8Array` byte-wise compare
  loop in TS (no built-in lexicographic comparator for typed arrays).
- The six-state Verdict can be encoded in TS as a string literal
  union: `"secure" | "secure-nodata" | "secure-nxdomain" | "insecure"
  | "bogus" | "indeterminate"`. Keep the spellings to preserve the
  JSON contract.
- The closest-encloser walk (ancestors from longest to shortest,
  hashing each) is straightforward in TS once `ComputeNSEC3Hash` is
  ported. Wildcard prefixing is plain string concatenation.

**Status.** Ships in dnsdata-go v0.2.0 (Week 4). Landed in dnsdata-js
[#22](https://github.com/shigeya/dnsdata-js/pull/22) — the canonical-name
helpers ship as `packages/core/src/lib/dnssec_util.ts`; the NSEC /
NSEC3 primitives extend the existing `dnssec_rr.ts` types. Coverage in
`tests/lib/dnssec_negative.spec.ts` + `tests/lib/dnssec_util.spec.ts`.

**Tracking:** landed-upstream — issue [shigeya/dnsdata-js#8](https://github.com/shigeya/dnsdata-js/issues/8), PR [#22](https://github.com/shigeya/dnsdata-js/pull/22).

---

## UP-005

CNAME and DNAME chasing in the chain validator, plus the
verdict-combination policy that lets multi-hop chains produce a
single coherent answer.

**Go source.** `verifier/alias.go` (`tryCNAME`, `tryDNAME`,
`synthesiseDNAMETarget`), `verifier/chain.go::Validate` and
`validateOneHop` / `resolveLeaf` factoring,
`verifier/result.go::AliasStep`, `verifier/chain.go::combineVerdicts`,
`verifier/chain.go::MaxAliasHops`.

**Public API.**

```go
// verifier
const MaxAliasHops = 10

type AliasStep struct {
    Type    string  `json:"type"`     // "cname" | "dname"
    From    string  `json:"from"`
    Target  string  `json:"target"`
    Zone    string  `json:"zone"`
    Verdict Verdict `json:"verdict"`
}

type Result struct {
    // ... existing fields ...
    Aliases []AliasStep `json:"aliases,omitempty"`
}
```

**Design decisions.**

1. **Outer loop over single-hop chain walks.** `Validate` calls
   `validateOneHop` per redirection, restarting from the root every
   time. This is wasteful (root, TLD, and often the parent zone are
   re-walked) but simple, and the `Result.Chain` field is
   deduplicated by zone name so the audit trail does not balloon. A
   future cache hook (DESIGN.md SHOULD #13) will eliminate the cost.
2. **Worst-of verdict combination.**
   `Bogus > Insecure > Indeterminate > Secure*`. The terminal hop's
   secure-negative kind (NoData vs NXDomain) is preserved when no
   stronger negative outcome supersedes it, so callers see the most
   specific successful classification.
3. **Loop detection by qname re-occurrence.** Tracking visited qnames
   in a set catches the common A → CNAME → A "ping-pong" without
   needing graph algorithms. RFC 1035 does not specify a precise
   loop rule; most validators settle for hop-count caps plus
   trivial re-visit detection.
4. **Hop cap at 10.** BIND uses 16 by default, unbound 12; we pick
   10 as a tighter default that still serves real-world chains and
   surfaces pathological cases quickly. The constant is exported as
   `MaxAliasHops` so callers can read it without depending on the
   string in `BogusReason`.
5. **DNAME synthesis follows RFC 6672 §5.3.1 strictly.** A DNAME at
   owner rewrites every name STRICTLY BELOW owner; a DNAME at qname
   itself does not synthesise. Mis-synthesis (qname does not end
   with owner) is treated as Bogus rather than silent fall-through.
6. **Alias signatures are zone-bound.** A CNAME at qname must verify
   under the current zone's keys. Cross-zone CNAMEs (where the
   target is in a different zone) trigger a fresh chain walk for
   the new qname on the next iteration; the previous zone's
   signature only had to cover the redirect itself.
7. **AliasStep carries a per-hop Verdict.** Worst-of combination
   computes the final verdict, but the per-hop Verdict lets callers
   pinpoint exactly which hop introduced the Insecure / Bogus
   contribution. The terminal hop is NOT recorded as an AliasStep
   (it is the answer itself); only the redirections are.
8. **No DS lookup for non-cut alias targets.** CNAME / DNAME targets
   often re-use the same zone or a near neighbour. The existing
   descend loop's "no DS → not a zone cut" handling continues to
   work because alias chasing is implemented above that layer.

**TS migration notes.**

- TS already parses CNAME and DNAME owner/value pairs in `zone/`;
  no new RR types needed.
- `synthesiseDNAMETarget` is plain label slicing — straightforward
  to port. The TS implementation should reuse the existing
  case-insensitive label compare.
- `Result.Aliases` is the only schema change at this stage. JSON
  consumers that ignore unknown fields keep working unchanged.
- A loop-detection set is a `Set<string>` in TS, lowercased to
  match the canonical form.
- The 10-hop cap is short enough to inline as a constant. The TS
  port can pick its own number but should document any deviation.

**Status.** Ships in dnsdata-go v0.2.0 (Week 5). Landed in dnsdata-js
[#23](https://github.com/shigeya/dnsdata-js/pull/23); CNAME / DNAME
chasing extends the existing `verifier.ts` chain walker rather than
introducing a new module.

**Tracking:** landed-upstream — issue [shigeya/dnsdata-js#9](https://github.com/shigeya/dnsdata-js/issues/9), PR [#23](https://github.com/shigeya/dnsdata-js/pull/23).

---

## UP-006

Wildcard-synthesised positive answer support. Detects responses
produced by wildcard expansion, reconstructs the wildcard owner so
the RRSIG over `*.<closest-encloser>` validates against records
appearing at the synthesised qname, and enforces the RFC 4035 §5.3.4
non-existence proof so the wildcard cannot be replayed at unrelated
names.

**Go source.** `dnssec/canon.go` (LabelCount, LastNLabels),
`dnssec/zone.go::CreateDigestTarget` (wildcard reconstruction
branch), `dnssec/zone.go::wireHeaderForOwner` (header construction
that decouples the owner from `rr.Label`), `verifier/wildcard.go`
(detectWildcard, proveQnameNonExistence),
`verifier/chain.go::resolveLeaf` (wildcard wiring),
`verifier/result.go::WildcardInfo`.

**Public API.**

```go
// dnssec
func LabelCount(name string) int
func LastNLabels(name string, n int) string

// verifier
type WildcardInfo struct {
    Source          string `json:"source"`
    ClosestEncloser string `json:"closestEncloser"`
    NextCloser      string `json:"nextCloser"`
    ProofReason     string `json:"proofReason"`
}

type Result struct {
    // ... existing fields ...
    Wildcard *WildcardInfo `json:"wildcard,omitempty"`
}
```

**Design decisions.**

1. **Wildcard handling lives in dnssec, detection lives in verifier.**
   The dnssec layer treats wildcard reconstruction as a pure
   property of `RRSIG.Labels`: when `Labels < LabelCount(name)`, the
   digest target is reconstructed at the wildcard owner. Signers
   that set `Labels` correctly produce matching digests; validators
   that read `Labels` produce matching digests. No new public method
   was needed. The verifier still needs to know synthesis occurred
   (to surface `Result.Wildcard` and to demand the non-existence
   proof), which is what `detectWildcard` does — by reading the same
   `Labels` field after a successful verify.
2. **No new verdict.** Wildcard synthesis with a valid non-existence
   proof is just Secure with an additional evidence field. This
   keeps the verdict enum at six states. Consumers who care about
   "did this answer come from a wildcard?" check `Result.Wildcard
   != nil`.
3. **Proof shapes are minimal.** RFC 4035 §5.3.4 requires proving
   the next-closer name does not exist. With NSEC that is a
   covering NSEC at any owner. With NSEC3 that is a covering NSEC3
   at H(next-closer). Both are existing primitives from UP-004.
4. **Detection runs only after positive verification.** This avoids
   doing closest-encloser computation on responses that will fail
   anyway, and matches what a real validator does in pipeline order.
5. **Reconstruction is bidirectional.** A signer that calls
   `Zone.CreateDigestTarget` with `rrsig.Labels` set to the wildcard
   semantics (excluding `*`) produces a wildcard-owner digest target
   from records at the wildcard owner. A validator that calls the
   same function on records at a synthesised qname with the
   matching `Labels` produces an identical digest target. Same
   function, same semantics on both sides.
6. **LabelCount / LastNLabels are exported.** Tests, signers, and
   other callers porting RFC 4034 §3.1.3 logic (e.g. wildcard
   support in NSEC validators) reuse the same helpers instead of
   reinventing the dot-splitting.

**TS migration notes.**

- The same Labels-driven branch in CreateDigestTarget translates
  literally: `if (rrsig.labels < labelCount(name)) { digestOwner =
  '*.' + lastNLabels(name, rrsig.labels); }`.
- `detectWildcard` is a one-liner that inspects `rrsig.labels` of
  whichever signature validated; the verifier-side wrapper can read
  the same array of signatures it already iterated.
- `proveQnameNonExistence` is structurally identical to the NXDOMAIN
  helper landed under UP-004; in many TS implementations it can be
  a thin re-export.
- The `WildcardInfo` JSON shape is small and additive; consumers
  ignoring unknown fields keep working unchanged.

**Status.** Ships in dnsdata-go v0.2.0 (Week 6). Landed in dnsdata-js
[#24](https://github.com/shigeya/dnsdata-js/pull/24); wildcard
synthesis extends the existing `dnssec_zone.ts` digest-target builder
and the `verifier.ts` chain walker. Coverage in
`tests/lib/verifier_wildcard.spec.ts`.

**Tracking:** landed-upstream — issue [shigeya/dnsdata-js#10](https://github.com/shigeya/dnsdata-js/issues/10), PR [#24](https://github.com/shigeya/dnsdata-js/pull/24).

---

## UP-007

### DoH (RFC 8484) client with provider failover

**Go source:** `resolver/doh/` (`doc.go`, `errors.go`, `client.go`,
`resolve.go`). Tests in `client_test.go`, `client_internal_test.go`,
`resolve_test.go`, `resolve_compat_test.go`. Reuses
`wire.BuildQuery` / `wire.ParseMessage` / `wire.RDataToString` with
`resolver/auth`.

**Why it matters for TS.** `dnsdata-js` currently ships
`packages/core/src/cli/resolver_doh.ts`, an old client that talks the
Google JSON DNS API and is wired only into the legacy `cli/` path. It
cannot satisfy the new `Verifier.Resolver` contract (which expects
`ResourceRecord[]` from a wire-format response) and predates the
shared EDNS(0)/DO query builder landed under UP-003. The Go side
already ships an RFC 8484 wire-format client; porting it back lets
the TS verifier consume DoH responses through the same surface as
the UDP/TCP auth client and unblocks deleting the legacy CLI
resolver.

**Public API surface.**

```go
type Client struct{ /* opaque */ }

func NewClient(opts ...Option) *Client
func (c *Client) Query(ctx context.Context, qname string, qtype uint16) ([]byte, error)
func (c *Client) QueryRaw(ctx context.Context, query []byte) ([]byte, error)
func (c *Client) Resolve(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error)
func (c *Client) Providers() []string

type Option func(*Client)
func WithHTTPClient(hc *http.Client) Option
func WithProviders(urls ...string) Option
func WithUserAgent(ua string) Option

func DefaultProviders() []string
const (
    DefaultGoogle     = "https://dns.google/dns-query"
    DefaultCloudflare = "https://cloudflare-dns.com/dns-query"
    DefaultQuad9      = "https://dns.quad9.net/dns-query"
    MediaType         = "application/dns-message"
)
```

**Design decisions worth carrying back to TS.**

1. **Wire format only.** POST with `Content-Type:
   application/dns-message`, body is exactly the bytes
   `wire.BuildQuery` produces, response is the raw DNS message. No
   JSON shim, no provider-specific parsers — the Google JSON path in
   `cli/resolver_doh.ts` is the legacy artefact to delete.
2. **Provider failover, in order.** `WithProviders(google, cf, q9)`
   (or the default list) is tried left to right. Network errors and
   non-2xx responses trigger failover; a 2xx with the right
   Content-Type returns immediately even when the embedded DNS RCODE
   is non-zero. RCODE != NOERROR is a DNS-level error, not a
   transport-level one — `Resolve` is what surfaces it as
   `ErrResolverResponse`.
3. **Errors compose via `errors.Join`.** `ErrAllProvidersFailed` is
   joined with the first inner error (`ErrUnexpectedStatus`,
   `ErrUnexpectedContentType`, or transport error) so
   `errors.Is(err, ErrAllProvidersFailed)` AND
   `errors.Is(err, ErrUnexpectedStatus)` both hold simultaneously.
   In TS the equivalent is subclass + `.cause`, mirroring the
   `AuthAllServersFailedError` shape from UP-003.
4. **EDNS(0) + DO bit in every query.** Built once by
   `wire.BuildQuery`, which is the same function the auth client
   uses, so the TS port should call the existing `build_query` /
   `build_query_with_id` rather than re-encoding the OPT record.
5. **No filesystem, no init() side effects.** Per DESIGN.md MUST
   NOT 23. TS port should match: no module-load `register_*` calls,
   no stdout writes — pure transport.
6. **Authority section is surfaced.** `Resolve` returns answer +
   authority records concatenated so the verifier can locate
   NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3). Additional
   section is intentionally dropped (glue + EDNS OPT, neither part
   of the validated rrset surface). This is the same shape the
   auth resolver ships under UP-003.
7. **HTTP-client injection for tests.** `WithHTTPClient` accepts a
   stubbed `*http.Client` so `httptest.Server` can drive the
   coverage. In TS the equivalent is an injected `fetch` function
   (`fetch_fn?: FetchFn`); production callers get
   `globalThis.fetch` (Node ≥ 18, browsers), tests pass a stub.
8. **64 KiB response cap.** `io.LimitReader(resp.Body, 64*1024)`
   defends against pathological providers. TS port should slice the
   ArrayBuffer to the same cap.

**TS migration notes.**

- Use Node's built-in `fetch` (≥ 18). The constructor should accept
  a `FetchFn` for tests and surface a typed error when no fetch is
  available, instead of crashing at first use.
- `context.Context` cancellation → `AbortSignal`. Compose the
  caller's signal with a per-request timeout via `AbortController`.
- `http.NewRequestWithContext` POST with `Uint8Array` body works
  out of the box in undici (Node fetch backend).
- For matching the file split, the natural TS shape is:
  - `src/lib/resolver/doh/errors.ts` ⇄ `errors.go`
  - `src/lib/resolver/doh/client.ts` ⇄ `client.go`
  - `src/lib/resolver/doh/resolve.ts` ⇄ `resolve.go` (via
    TypeScript declaration merging on `DoHClient.prototype.resolve`)
  - `src/lib/resolver/doh/index.ts` barrel that imports `resolve.ts`
    so any consumer pulling `DoHClient` also gets the method.
- Method value satisfies `verifier.Resolver.query`:
  `new Verifier({ resolver: { query: client.resolve.bind(client) } })`.

**Status.** Ships in dnsdata-go v0.1.0. Landed in dnsdata-js
P1 of `REFACTOR_PLAN.md` as `packages/core/src/lib/resolver/doh/`
with paired spec files under `tests/lib/resolver/doh/`.

**Tracking:** in-progress — port landed locally in dnsdata-js; PR
not yet opened (P1 of the in-flight dnsdata-js refactor).

---

## UP-008

### Pluggable Cache layer for the verifier (DESIGN.md SHOULD #13)

**Go source:** `verifier/cache.go`, `verifier/verifier.go::WithCache`,
`verifier/chain.go::loadRecords` (cache lookup + put around the
`Resolver.Query` call, plus `applyRecords` helper shared with the
fresh-fetch path). Tests in `verifier/cache_test.go`.

**Why it matters for TS.** Validating many domains in a batch (the
primary mailsec-probe use case) re-walks the same root and TLD
DNSKEY/DS rrsets per call. The `Validate` outer loop already
restarts from the root on every alias hop. Without a cache the
verifier issues O(zones × validate-calls) resolver requests against
data that is essentially immutable for the duration of a batch.
A pluggable cache lets a caller share one in-memory store across
calls and reduce the cost to the leaf path.

**Public API surface.**

```go
type Cache interface {
    Get(name string, qtype uint16) (records []*zone.ResourceRecord, ok bool)
    Put(name string, qtype uint16, records []*zone.ResourceRecord)
}

type MemoryCache struct{ /* opaque */ }

func NewMemoryCache() *MemoryCache
func (c *MemoryCache) Len() int

func WithCache(c Cache) Option
```

`verifier.WithCache(nil)` is equivalent to not passing the option —
the verifier behaves as if no cache layer existed.

**Design decisions worth carrying back to TS.**

1. **(name, qtype) granularity.** The smallest meaningful unit is one
   rrset, and the verifier already issues one resolver query per
   rrset. Per-record caching would require re-sorting / re-grouping
   on every read; per-zone caching would force callers to track zone
   cuts. (name, qtype) lines up 1:1 with `Resolver.Query`'s shape.
2. **NODATA is a valid cache entry.** A successful resolver response
   with zero records is materially different from "we never asked".
   `Get` MUST signal a hit (`ok=true` in Go, non-`undefined` in TS)
   even when the records list is empty. Tests assert this directly.
3. **Errors are never cached.** Only successful resolver responses
   feed `Put`. A failure leaves the cache untouched so the next
   call has a chance to retry the underlying transport.
4. **No TTL by default.** The DESIGN clause specifically calls out
   "across a batch run". `MemoryCache` is unbounded and entries
   never expire; callers who need TTL-aware behaviour layer their
   own implementation behind `Cache`. The interface intentionally
   does not surface TTL — implementations inspect
   `ResourceRecord.TTL` themselves if they want it.
5. **Concurrency.** The chain walker itself is single-goroutine per
   `Validate` call, but real callers fan out across goroutines.
   `MemoryCache` uses `sync.RWMutex`; the interface contract says
   implementations MUST be safe for concurrent Get/Put.
6. **Shared `applyRecords` helper.** Cache hits and fresh fetches
   both flow through the same record-application path so
   `result.Evidence` is populated identically. A caller cannot tell
   a cached run from a cold one by inspecting the Result. This is
   what lets the cache be added without changing any existing test
   expectations.
7. **`WithCache(nil)` is a no-op.** Defensive: callers that build
   options programmatically can pass an optional cache without
   special-casing the nil branch on their end.

**TS migration notes.**

- The Go `(records, ok)` tuple maps to TS `records | undefined`:
  `undefined` means miss, an empty array means NODATA hit. This is
  the most idiomatic shape and avoids a tuple wrapper.
- `MemoryCache` uses a `Map<string, ResourceRecord[]>` keyed by
  `${name} ${qtype}` (a literal space is illegal in a normalised
  DNS name per RFC 1035 §2.3.1, so the separator is unambiguous).
  No external dependency.
- `VerifierOptions.cache?: Cache` is the natural injection point;
  nullish is treated as "no cache".
- TS does not need a separate concurrency story because the JS
  event loop serialises operations on a Map; the same interface
  contract still holds for consumers that share a cache across
  await points.

**Status.** Shipped in dnsdata-go
[#21](https://github.com/shigeya/dnsdata-go/pull/21) and ported to
dnsdata-js [#25](https://github.com/shigeya/dnsdata-js/pull/25)
(`packages/core/src/verifier/cache.ts` with paired spec at
`tests/verifier/verifier_cache.spec.ts`). Both PRs landed on the
respective `main` branches.

**Tracking:** landed-upstream.

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
