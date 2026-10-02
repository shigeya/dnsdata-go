package doh

import (
	"context"
	"errors"
	"fmt"

	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/resolver/internal/message"
)

// ErrResolverResponse classifies failures returned by [Client.Resolve]
// that originate from the DNS response itself (malformed message,
// parse failure) rather than from the HTTP transport.
//
// A non-zero RCODE is NOT an error: it surfaces in
// [resolver.Response.RCode] so callers can distinguish NXDOMAIN /
// NODATA / SERVFAIL without parsing error strings. Callers that want
// the legacy "any non-zero RCODE is fatal" semantics should test
// `resp.RCode != 0` after a successful call.
var ErrResolverResponse = errors.New("doh: bad response")

// Resolve runs a DoH query for (name, qtype) against the configured
// providers, parses the response, and returns its answer + authority
// section records as presentation-form [zone.ResourceRecord] values,
// alongside the AD bit and RCODE from the response header.
//
// Both answer and authority sections are included so the verifier can
// locate NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3 places those in
// the authority section of a NODATA / NXDOMAIN / no-DS response). The
// additional section is still ignored — it carries glue and EDNS OPT,
// neither of which is part of the validated rrset surface.
func (c *Client) Resolve(ctx context.Context, name string, qtype uint16) (resolver.Response, error) {
	raw, err := c.Query(ctx, name, qtype)
	if err != nil {
		return resolver.Response{}, err
	}
	resp, err := message.ToResponse(raw)
	if err != nil {
		return resolver.Response{}, fmt.Errorf("%w: %v", ErrResolverResponse, err)
	}
	return resp, nil
}
