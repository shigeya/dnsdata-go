package zone

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// EUI is the shared RR handler for EUI48 (RFC 7043 §3) and EUI64 (§4).
// The two records have the same wire and presentation shape; only the
// fixed address length differs (6 vs 8 octets), captured by ByteLen.
//
// Wire format: address(ByteLen octets, network byte order).
//
// Presentation format: hex octets separated by hyphens, e.g.
// "00-00-5e-00-53-2a" for EUI48 or "00-00-5e-ef-10-00-00-2a" for EUI64.
type EUI struct {
	rr *ResourceRecord

	ByteLen uint8
	Address []byte
}

// ParseEUI constructs an EUI handler from RR presentation form for the
// given fixed length (6 = EUI48, 8 = EUI64). Returns
// [ErrPresentationFormat] when the wrong number of octets is supplied or
// any octet fails to hex-decode.
func ParseEUI(rr *ResourceRecord, value string, byteLen uint8) (*EUI, error) {
	typeName := "EUI48"
	if byteLen == 8 {
		typeName = "EUI64"
	}
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != int(byteLen) {
		return nil, fmt.Errorf("%w: %s: expected %d hex octets separated by hyphens: %q",
			ErrPresentationFormat, typeName, byteLen, value)
	}
	addr := make([]byte, byteLen)
	for i, p := range parts {
		if len(p) != 2 {
			return nil, fmt.Errorf("%w: %s: octet %d %q is not two hex digits",
				ErrPresentationFormat, typeName, i, p)
		}
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: octet %d hex: %v",
				ErrPresentationFormat, typeName, i, err)
		}
		addr[i] = b[0]
	}
	return &EUI{rr: rr, ByteLen: byteLen, Address: addr}, nil
}

// WireBody emits `rdlen(2) + address(ByteLen)`.
func (e *EUI) WireBody(b *wire.Builder) error {
	b.AppendUint16(uint16(e.ByteLen))
	b.AppendBytes(e.Address)
	return nil
}

// Clone returns a deep copy of e.
func (e *EUI) Clone() RecordHandler {
	return &EUI{
		rr:      e.rr,
		ByteLen: e.ByteLen,
		Address: append([]byte(nil), e.Address...),
	}
}

// eui48Factory adapts [ParseEUI] with ByteLen=6 into [HandlerFactory].
func eui48Factory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseEUI(rr, value, 6)
	if err != nil {
		return nil
	}
	return h
}

// eui64Factory adapts [ParseEUI] with ByteLen=8 into [HandlerFactory].
func eui64Factory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseEUI(rr, value, 8)
	if err != nil {
		return nil
	}
	return h
}
