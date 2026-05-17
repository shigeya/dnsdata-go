# UPSTREAM_FEEDBACK.md

Items discovered while implementing dnsdata-go that **should be reflected back
into dnsdata-js (TypeScript)**. The reverse-direction (Go → TS) feedback channel
for co-design.

Each item is intended to be transcribed into a dnsdata-js issue / PR /
DESIGN.md change. Once an item reaches `fixed-upstream`, the corresponding
Go-side deviation comment may be removed.

## Summary

| ID | Description | TS source | Type | Status |
|---|---|---|---|---|
| [UF-001](#uf-001) | `domain_name2wire`'s `\| 0x20` lowercase corrupts the underscore byte (0x5F → 0x7F) | `dns_wire.ts:16` | bug | pending |
| [UF-002](#uf-002) | No label / name length validation | `dns_wire.ts:1-32` | robustness | pending |
| [UF-003](#uf-003) | Unknown enum inputs throw bare `RangeError`; no typed classification | `dns_type_table.ts:18,31,59,86,…` | api-shape | pending |

Status legend:

- `pending` — handled on the Go side; not yet addressed upstream
- `filed` — issue / PR opened against dnsdata-js
- `fixed-upstream` — landed in dnsdata-js; Go-side deviation note can be removed

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

## Procedure for new entries

When a new deviation is introduced:

1. Append a new `UF-NNN` section to this file (numerically continuous).
2. Add a row to the Summary table.
3. From the Go source / test that embodies the deviation, reference the ID
   (`// UPSTREAM_FEEDBACK.md UF-NNN`).
4. As the item progresses to `filed` / `fixed-upstream`, update the table.

For the opposite direction (TS → Go requirements), see `DESIGN.md §4`.
