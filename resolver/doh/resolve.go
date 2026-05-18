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
// providers, parses the response, and returns its answer + authority
// section records as presentation-form [zone.ResourceRecord] values.
//
// Both sections are included so the verifier can locate NSEC / NSEC3
// negative proofs (RFC 4035 §3.1.3 places those in the authority
// section of a NODATA / NXDOMAIN / no-DS response). The additional
// section is still ignored — it carries glue and EDNS OPT, neither of
// which is part of the validated rrset surface.
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

	out := make([]*zone.ResourceRecord, 0, len(msg.Answer)+len(msg.Authority))
	for _, rr := range msg.Answer {
		rec, err := rawRRToResourceRecord(msg.Raw, rr)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	for _, rr := range msg.Authority {
		rec, err := rawRRToResourceRecord(msg.Raw, rr)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func rawRRToResourceRecord(raw []byte, rr wire.RawRR) (*zone.ResourceRecord, error) {
	value, err := wire.RDataToString(raw, rr.Type, rr.RData, rr.RDataStart)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResolverResponse, err)
	}
	rec, err := zone.NewResourceRecord(rr.Name, rr.TTL, rr.Class, rr.Type, value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResolverResponse, err)
	}
	return rec, nil
}
