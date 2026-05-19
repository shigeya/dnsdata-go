// Package resolver defines the response shape returned by every DNS
// resolver backend in this module (resolver/auth, resolver/doh, and any
// future transport).
//
// Backends populate [Response] verbatim from the wire-format header and
// answer + authority sections. RCODE classification is left to the
// caller: transport-level failures (network, parse, HTTP) come back as
// errors with a zero Response, while a parsed DNS response — including
// SERVFAIL, NXDOMAIN, and other non-zero RCODEs — comes back as a
// non-error Response with RCode populated. Callers that need to treat
// non-zero RCODE as an error (such as [verifier.Verifier]) should do
// so explicitly.
package resolver

import "github.com/shigeya/dnsdata-go/zone"

// Response is the structured return of a single resolver query. It
// carries the answer + authority records together with the two header
// fields callers commonly want to observe directly:
//
//   - AD: the responder's "I validated this" claim (RFC 4035 §3). Only
//     trustworthy on a channel you trust; meaningless for direct
//     authoritative queries.
//   - RCode: the low 4 bits of the response flags (RFC 1035 §4.1.1).
//     0 (NOERROR) is the success case; non-zero values are returned as
//     data so callers can distinguish NXDOMAIN from NODATA from
//     SERVFAIL without parsing error strings.
type Response struct {
	Records []*zone.ResourceRecord
	AD      bool
	RCode   uint8
}
