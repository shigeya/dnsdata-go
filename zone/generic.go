package zone

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// genericRDataMarker introduces the RFC 3597 §5 generic RDATA form.
const genericRDataMarker = `\#`

// maxRDataLength is the largest RDLENGTH a uint16 can carry.
const maxRDataLength = 0xFFFF

// ParseGenericRData parses the RFC 3597 §5 generic RDATA form
// `\# <length> <hex>` (the hex may be split by whitespace). isGeneric
// is false, with a nil error, when value is not in that form. A
// declared length that does not match the hex, or malformed hex, is an
// [ErrPresentationFormat].
func ParseGenericRData(value string) (rdata []byte, isGeneric bool, err error) {
	fields := strings.Fields(value)
	if len(fields) == 0 || fields[0] != genericRDataMarker {
		return nil, false, nil
	}
	if len(fields) < 2 {
		return nil, true, fmt.Errorf("%w: generic RDATA: missing length in %q", ErrPresentationFormat, value)
	}
	declared, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil || declared > maxRDataLength {
		return nil, true, fmt.Errorf("%w: generic RDATA: length %q", ErrPresentationFormat, fields[1])
	}
	raw, err := hex.DecodeString(strings.Join(fields[2:], ""))
	if err != nil {
		return nil, true, fmt.Errorf("%w: generic RDATA hex: %v", ErrPresentationFormat, err)
	}
	if uint64(len(raw)) != declared {
		return nil, true, fmt.Errorf("%w: generic RDATA: length %d, hex has %d octets",
			ErrPresentationFormat, declared, len(raw))
	}
	return raw, true, nil
}

// GenericRData returns the RDATA octets when rr.Value is in the RFC 3597
// generic form. isGeneric is false for any other value.
func (rr *ResourceRecord) GenericRData() (rdata []byte, isGeneric bool, err error) {
	return ParseGenericRData(rr.Value)
}

// NewResourceRecordFromRData builds a record whose value is the RFC 3597
// generic form of rdata. The record's wire form is rdata verbatim for
// any type, which keeps the canonical form of received data intact.
func NewResourceRecordFromRData(label string, ttl uint32, class, rrtype uint16, rdata []byte) (*ResourceRecord, error) {
	if len(rdata) > maxRDataLength {
		return nil, fmt.Errorf("%w: RDATA length %d", ErrRDataFormat, len(rdata))
	}
	return &ResourceRecord{
		Label: label,
		TTL:   ttl,
		Class: class,
		Type:  rrtype,
		Value: wire.FormatGenericRData(rdata),
	}, nil
}

// writeWireGeneric appends rdlength + rdata.
func writeWireGeneric(b *wire.Builder, rdata []byte) {
	b.AppendUint16(uint16(len(rdata)))
	b.AppendBytes(rdata)
}

// handlerFromGeneric builds the typed handler for a record held in
// generic form, decoding the octets by type. It is only consulted when
// a factory is registered for the type, so handler registration stays
// opt-in. Returns nil when the octets do not decode.
func handlerFromGeneric(rr *ResourceRecord, factory HandlerFactory, rdata []byte) RecordHandler {
	switch rr.Type {
	case types.TypeTLSA, types.TypeSMIMEA:
		return factory(rr, tlsaPresentation(rdata))
	case types.TypeSVCB, types.TypeHTTPS:
		h, err := svcbFromRData(rr, rdata)
		if err != nil {
			return nil
		}
		return h
	}
	pres, err := wire.RDataToString(rdata, rr.Type, rdata, 0)
	if err != nil || strings.HasPrefix(pres, genericRDataMarker) {
		return nil
	}
	return factory(rr, pres)
}

// tlsaPresentation renders TLSA / SMIMEA octets as `usage selector
// matching-type hex`. Short input yields a value the parser rejects.
func tlsaPresentation(rdata []byte) string {
	if len(rdata) < 3 {
		return ""
	}
	return fmt.Sprintf("%d %d %d %s", rdata[0], rdata[1], rdata[2], hex.EncodeToString(rdata[3:]))
}

// TXTStrings returns the character-strings of a TXT record, whether its
// value is in presentation form or in RFC 3597 generic form.
func (rr *ResourceRecord) TXTStrings() ([]string, error) {
	if rr.Type != types.TypeTXT {
		return nil, fmt.Errorf("%w: TXTStrings on type %s", ErrRDataFormat, types.RRTypeName(rr.Type))
	}
	raw, isGeneric, err := rr.GenericRData()
	if err != nil {
		return nil, err
	}
	if !isGeneric {
		return parseTXTValue(rr.Value), nil
	}
	return splitCharacterStrings(raw)
}

// splitCharacterStrings splits RDATA made of RFC 1035 §3.3
// <character-string>s.
func splitCharacterStrings(rdata []byte) ([]string, error) {
	out := []string{}
	for pos := 0; pos < len(rdata); {
		n := int(rdata[pos])
		pos++
		if pos+n > len(rdata) {
			return nil, fmt.Errorf("%w: character-string truncated", ErrRDataFormat)
		}
		out = append(out, string(rdata[pos:pos+n]))
		pos += n
	}
	return out, nil
}
