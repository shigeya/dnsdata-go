// Package wire provides DNS wire-format encoding and decoding primitives:
// domain-name codec and a byte-buffer builder for assembling RDATA in
// big-endian byte order.
//
// Port of dns_wire.ts and dns_wire_util.ts from dnsdata-js.
// [DomainNameToWire] lowercases ASCII letters per RFC 4034 §6.2 and
// enforces RFC 1035 §2.3.4 label / name length limits;
// [WireToDomainName] rejects compression pointers and truncated input.
package wire
