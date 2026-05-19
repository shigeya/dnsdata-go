// Package doh implements a DNS-over-HTTPS client per RFC 8484.
//
// The client speaks the application/dns-message wire format, picks
// providers in caller-supplied order with automatic failover on
// transport errors or non-2xx responses, and includes an EDNS(0) OPT
// pseudo-RR with the DO bit set so DNSSEC RRSIGs are returned.
//
// # Default provider order
//
// When [NewClient] is called without [WithProviders], the client tries
// providers in this order:
//
//  1. Cloudflare (https://cloudflare-dns.com/dns-query)
//  2. Google     (https://dns.google/dns-query)
//  3. Quad9      (https://dns.quad9.net/dns-query)
//
// Failover is sequential: each provider is given up to the underlying
// HTTP client timeout (10s by default) before the next one is tried.
// The list is therefore ordered by expected tail-latency stability, not
// by single-shot peak speed. The reasoning, provider by provider:
//
//   - Cloudflare leads because its anycast PoP footprint is the most
//     evenly distributed worldwide (notably strong in Asia/Pacific and
//     Europe). Tail latency from arbitrary client locations is more
//     predictable than Google's, whose paths can vary by ISP and route
//     announcement. Cloudflare also publishes a no-logging-beyond-24h
//     policy that is acceptable for a generic library default.
//
//   - Google is the most reliable fallback. Capacity is effectively
//     unlimited and outages are rare, but route paths can be noticeably
//     slower than Cloudflare from some Asian and South-American
//     transit. Keeping Google as the second choice gives consumers a
//     well-known fallback without paying its route variance on every
//     query.
//
//   - Quad9 is last because it applies a malicious-domain block list:
//     queries for names on its threat feed return NXDOMAIN regardless
//     of authoritative state. For a DNSSEC chain validator, this can
//     surface as a spurious INSECURE or NXDOMAIN result on the rare
//     domain that Quad9 has chosen to filter. Using Quad9 only after
//     both upstream-faithful resolvers have failed avoids that pitfall
//     in the common case while still providing a third option for
//     resilience.
//
// Consumers with regional knowledge (e.g. internal resolvers, regional
// ISP-provided DoH, EU sovereignty constraints) should override the
// order with [WithProviders] rather than relying on the default.
//
// # Out of scope
//
// The package intentionally returns raw response bytes; structured
// parsing of the response message lives elsewhere. This keeps doh
// focused on the transport concern and lets the parser evolve
// independently.
//
// The client does not race providers in parallel and does not
// speculatively cancel in-flight queries. Sequential failover with a
// caller-tuned timeout was chosen over speculative execution to keep
// the network footprint predictable.
//
// Per DESIGN.md MUST NOT 23, doh writes nothing to the filesystem,
// no init() side effects, no calls to os.Exit. All filesystem and
// logging concerns are the caller's responsibility.
package doh
