package zone

import (
	"encoding/base64"
	"fmt"

	"github.com/shigeya/dnsdata-go/wire"
)

// OPENPGPKEY is the RR handler for OPENPGPKEY (RFC 7929).
//
// Wire format (§2.1): the entire RDATA is the raw OpenPGP Transferable
// Public Key (RFC 4880 §11.1); no additional structure or length prefix
// inside RDATA.
//
// Presentation format (§2.2): base64-encoded key material (RFC 4648 §4),
// which may be split across whitespace in zone files.
type OPENPGPKEY struct {
	rr *ResourceRecord

	KeyData []byte
}

// ParseOPENPGPKEY constructs an OPENPGPKEY handler from RR presentation
// form. Returns [ErrPresentationFormat] for an empty value or invalid
// base64.
func ParseOPENPGPKEY(rr *ResourceRecord, value string) (*OPENPGPKEY, error) {
	b64 := stripASCIIWhitespace(value)
	if b64 == "" {
		return nil, fmt.Errorf("%w: OPENPGPKEY: empty key data", ErrPresentationFormat)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: OPENPGPKEY base64: %v", ErrPresentationFormat, err)
	}
	return &OPENPGPKEY{rr: rr, KeyData: data}, nil
}

// WireBody emits `rdlen(2) + key_data`.
func (o *OPENPGPKEY) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(len(o.KeyData)))
	b.AppendBytes(o.KeyData)
	return nil
}

// Clone returns a deep copy of o.
func (o *OPENPGPKEY) Clone() RecordHandler {
	return &OPENPGPKEY{
		rr:      o.rr,
		KeyData: append([]byte(nil), o.KeyData...),
	}
}

// openpgpkeyFactory adapts [ParseOPENPGPKEY] into [HandlerFactory].
// Returns nil on parse failure so the zone parser falls back to keeping
// the value as text (TS parity).
func openpgpkeyFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseOPENPGPKEY(rr, value)
	if err != nil {
		return nil
	}
	return h
}
