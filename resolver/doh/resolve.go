package doh

import (
	"context"
	"errors"
	"fmt"

	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// ErrResolverResponse classifies failures returned by [Client.Resolve]
// that originate from the DNS response itself (malformed message,
// non-zero RCODE for unrecoverable cases, etc.) rather than from the
// HTTP transport.
var ErrResolverResponse = errors.New("doh: bad response")

// Resolve runs a DoH query for (name, qtype) against the configured
// providers, parses the response, and returns its answer section as
// presentation-form [zone.ResourceRecord] values.
//
// The returned slice contains every record in the answer section
// (including RRSIGs covering the rrset), making it directly usable by
// a `verifier.Resolver`-compatible caller. Authority and additional
// sections are intentionally ignored at this layer; NSEC negative
// proofs that live there are scoped for the future Insecure-verdict
// support.
//
// A non-zero RCODE other than NOERROR (0) returns a wrapped
// [ErrResolverResponse]; SERVFAIL surfaces because the caller often
// wants to differentiate it from "DNS data not signed".
func (c *Client) Resolve(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error) {
	raw, err := c.Query(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	msg, err := wire.ParseMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResolverResponse, err)
	}
	if rc := msg.Header.RCode(); rc != 0 {
		return nil, fmt.Errorf("%w: RCODE=%d", ErrResolverResponse, rc)
	}

	out := make([]*zone.ResourceRecord, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		value, err := wire.RDataToString(msg.Raw, rr.Type, rr.RData, rr.RDataStart)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrResolverResponse, err)
		}
		rec, err := zone.NewResourceRecord(rr.Name, rr.TTL, rr.Class, rr.Type, value)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrResolverResponse, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
