// Package message turns a DNS response message into a
// [resolver.Response]. The auth, DoH and DoT clients share it.
package message

import (
	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// ToResponse parses raw and returns its answer and authority records
// as presentation-form [zone.ResourceRecord] values, with the AD bit
// and RCODE of its header. The authority section carries the NSEC /
// NSEC3 proofs a verifier needs (RFC 4035 §3.1.3); the additional
// section (glue, EDNS OPT) is ignored. Errors come from parsing the
// message or a record; callers wrap them with their own sentinel.
func ToResponse(raw []byte) (resolver.Response, error) {
	msg, err := wire.ParseMessage(raw)
	if err != nil {
		return resolver.Response{}, err
	}
	out := resolver.Response{
		AD:      msg.Header.AD(),
		RCode:   msg.Header.RCode(),
		Records: make([]*zone.ResourceRecord, 0, len(msg.Answer)+len(msg.Authority)),
	}
	for _, rr := range append(append([]wire.RawRR(nil), msg.Answer...), msg.Authority...) {
		rec, err := toResourceRecord(msg.Raw, rr)
		if err != nil {
			return resolver.Response{}, err
		}
		out.Records = append(out.Records, rec)
	}
	return out, nil
}

func toResourceRecord(raw []byte, rr wire.RawRR) (*zone.ResourceRecord, error) {
	value, err := wire.RDataToString(raw, rr.Type, rr.RData, rr.RDataStart)
	if err != nil {
		return nil, err
	}
	return zone.NewResourceRecord(rr.Name, rr.TTL, rr.Class, rr.Type, value)
}
