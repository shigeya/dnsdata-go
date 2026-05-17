package dnssec

import "errors"

// Sentinel errors for the dnssec package. Concrete errors wrap one of
// these so callers can classify failures with [errors.Is].
//
//   - [ErrPresentationFormat] — text presentation-form parse failure
//     (mirrors `DNSZonePresentationFormatError` in dns_exception.ts)
//   - [ErrUnsupportedAlgorithm] — algorithm number recognised but not
//     implemented (e.g. RSAMD5, GOST, Ed448)
//   - [ErrInvalidKey] — DNSKEY RDATA inconsistent with its algorithm
//     (wrong public-key length, malformed RFC 3110 RSA encoding, ...)
//   - [ErrInvalidSignature] — RRSIG signature length / format wrong for
//     its algorithm
//   - [ErrDNSSEC] — generic dnssec error; rarely returned directly
var (
	ErrDNSSEC               = errors.New("dnssec error")
	ErrPresentationFormat   = errors.New("dnssec presentation format error")
	ErrUnsupportedAlgorithm = errors.New("unsupported dnssec algorithm")
	ErrInvalidKey           = errors.New("invalid dnssec key")
	ErrInvalidSignature     = errors.New("invalid dnssec signature")
)
