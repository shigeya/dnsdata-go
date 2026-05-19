package zone

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// RP is the RR handler for RP / Responsible Person (RFC 1183 §2.2).
//
// Wire format: mbox-dname(uncompressed wire name) + txt-dname(uncompressed
// wire name).
//
// Presentation format: two whitespace-separated domain names. Either name
// may be "." to signal "no mailbox / no TXT record" per RFC 1183 §2.2.
type RP struct {
	rr *ResourceRecord

	Mbox     string
	TxtDName string
}

// ParseRP constructs an RP handler from RR presentation form. Returns
// [ErrPresentationFormat] when fewer than two domain-name tokens appear.
func ParseRP(rr *ResourceRecord, value string) (*RP, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: RP: expected mbox-dname and txt-dname: %q", ErrPresentationFormat, value)
	}
	return &RP{rr: rr, Mbox: parts[0], TxtDName: parts[1]}, nil
}

// WireBody emits `rdlen(2) + mbox-dname-wire + txt-dname-wire`.
//
// Returns [ErrRDataFormat] if either domain name cannot be wire-encoded.
func (r *RP) WireBody(b *wire.Builder) error {
	mbox, err := wire.DomainNameToWire(r.Mbox)
	if err != nil {
		return fmt.Errorf("%w: RP mbox %q: %v", ErrRDataFormat, r.Mbox, err)
	}
	txt, err := wire.DomainNameToWire(r.TxtDName)
	if err != nil {
		return fmt.Errorf("%w: RP txt-dname %q: %v", ErrRDataFormat, r.TxtDName, err)
	}
	b.AppendUint16(uint16(len(mbox) + len(txt)))
	b.AppendBytes(mbox)
	b.AppendBytes(txt)
	return nil
}

// Clone returns a copy of r.
func (r *RP) Clone() RecordHandler {
	return &RP{rr: r.rr, Mbox: r.Mbox, TxtDName: r.TxtDName}
}

// rpFactory adapts [ParseRP] into [HandlerFactory]. Returns nil on parse
// failure so the zone parser falls back to keeping the value as text
// (TS parity).
func rpFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseRP(rr, value)
	if err != nil {
		return nil
	}
	return h
}
