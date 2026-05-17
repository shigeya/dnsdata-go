// Package zone provides DNS resource records and a master-file (zone-file)
// parser.
//
// It is a port of dns_zone.ts (and the tiny dns_exception.ts) from
// dnsdata-js. The TypeScript design — a registry of RR-type handlers
// extended by other packages such as dnssec_rr — is preserved so the
// upcoming dnssec/ port can plug DNSKEY / RRSIG / DS / NSEC / NSEC3
// handlers in the same way.
//
// Design notes that deviate from the TS source are tracked in
// UPSTREAM_FEEDBACK.md at the repository root.
package zone
