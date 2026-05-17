// Package types provides DNS protocol enumerations (opcode, rcode, RR type,
// RR class, DNSSEC algorithm) and their string conversions.
//
// The numeric values follow the IANA registry. RR types are exposed as
// untyped uint16 constants (e.g. [TypeA] = 1) so they interoperate with
// miekg/dns and other libraries that expect raw wire-format values.
//
// String conversion functions match the API of the TypeScript source they
// were ported from (dnsdata-js): every Xxx-to-string function returns an
// error for unknown inputs rather than panicking.
package types
