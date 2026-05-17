// Package auth is a UDP / TCP DNS client suited to direct queries
// against caller-specified servers (authoritative name servers,
// recursive resolvers, or a local stub like dnsdata-go in
// mailsec-probe's `--dns-server` mode).
//
// Wire-format details:
//
//   - Queries are built with [wire.BuildQuery], sharing the EDNS(0) /
//     DO-bit configuration with resolver/doh.
//   - UDP is tried first. If the response has the TC (truncation) flag
//     set, the same query is replayed on TCP per RFC 1035 §4.2.1.
//   - TCP frames are prefixed with a 2-byte big-endian length per
//     RFC 1035 §4.2.2.
//
// Multi-server failover is identical in shape to resolver/doh: the
// configured servers are tried in order; the first one that returns
// a usable response wins.
//
// Per DESIGN.md MUST 9, the API is designed to interoperate with
// mailsec-probe's `--dns-server <ip>` option — the caller supplies
// address(es) and a deadline via context; nothing is read from
// /etc/resolv.conf, no filesystem touches.
package auth
