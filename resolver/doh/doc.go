// Package doh implements a DNS-over-HTTPS client per RFC 8484.
//
// The client speaks the application/dns-message wire format, picks
// providers in caller-supplied order with automatic failover on
// transport errors or non-2xx responses, and includes an EDNS(0) OPT
// pseudo-RR with the DO bit set so DNSSEC RRSIGs are returned.
//
// Default providers (Google → Cloudflare → Quad9) are exposed as
// constants and are used when [NewClient] is called without
// [WithProviders].
//
// The package intentionally returns raw response bytes; structured
// parsing of the response message lives elsewhere (Week 3, when the
// chain validator lands). This keeps doh focused on the transport
// concern and lets the parser evolve independently.
//
// Per DESIGN.md MUST NOT 23, doh writes nothing to the filesystem,
// no init() side effects, no calls to os.Exit. All filesystem and
// logging concerns are the caller's responsibility.
package doh
