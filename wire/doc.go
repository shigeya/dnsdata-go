// Package wire provides DNS wire-format encoding and decoding primitives:
// domain-name codec and a byte-buffer builder for assembling RDATA in
// big-endian byte order.
//
// This is a port of dns_wire.ts and dns_wire_util.ts from dnsdata-js
// with two deliberate deviations, both tracked for upstream backport in
// UPSTREAM_FEEDBACK.md at the repository root:
//
//   - UF-001: [DomainNameToWire] lowercases ASCII letters per RFC 4034
//     §6.2 instead of the TypeScript source's `b | 0x20` shortcut, which
//     corrupts the underscore (0x5F) byte commonly seen in DKIM / DMARC /
//     TLSA owner names.
//   - UF-002: [DomainNameToWire] validates label length (≤63 octets) and
//     name length (≤255 octets); [WireToDomainName] rejects compression
//     pointers and truncated input. The TypeScript source performs none
//     of these checks.
package wire
