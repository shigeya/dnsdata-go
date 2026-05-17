// Package dnssec provides DNSSEC primitives — DNSKEY / RRSIG / DS / NSEC /
// NSEC3 records and root trust anchors — used by the chain validator.
//
// The package corresponds to dnssec_rr.ts, dnssec_zone.ts,
// dnssec_key_loader.ts, and root_anchors.ts in dnsdata-js. Currently
// only root_anchors.ts is ported; the rest will land in subsequent
// commits.
//
// Crypto primitives come from the Go standard library only
// (crypto/rsa, crypto/ecdsa, crypto/ed25519, crypto/sha1, crypto/sha256,
// crypto/sha512). No dependency on miekg/dns.
package dnssec
