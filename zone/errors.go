package zone

import "errors"

// Error categories mirroring dns_exception.ts:
//
//   - [ErrZone] — generic zone-related failure (DNSZoneException)
//   - [ErrPresentationFormat] — text presentation-form parse failure
//     (DNSZonePresentationFormatError)
//   - [ErrRDataFormat] — RDATA structure or value invalid
//     (DNSZoneRDataFormatError)
//
// Concrete errors wrap one of these sentinels so callers can classify
// failures with [errors.Is].
var (
	ErrZone               = errors.New("zone error")
	ErrPresentationFormat = errors.New("zone presentation format error")
	ErrRDataFormat        = errors.New("zone rdata format error")
)
