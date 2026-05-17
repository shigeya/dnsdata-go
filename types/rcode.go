package types

import "fmt"

// RCode constants per RFC 1035 / 6891 / 2845.
//
// Values 0..15 fit in the 4-bit DNS header field. Values >= 16 are EDNS
// extended rcodes (assembled from the OPT record).
const (
	RCodeNoError  uint16 = 0
	RCodeFormErr  uint16 = 1
	RCodeServFail uint16 = 2
	RCodeNXDomain uint16 = 3
	RCodeNotImpl  uint16 = 4
	RCodeRefused  uint16 = 5
	// BIND_UPDATE rcodes (RFC 2136)
	RCodeYXDomain uint16 = 6
	RCodeYXRRSet  uint16 = 7
	RCodeNXRRSet  uint16 = 8
	RCodeNotAuth  uint16 = 9
	RCodeNotZone  uint16 = 10
	// EDNS / TSIG extended rcodes
	RCodeBadVers uint16 = 16 // also BADSIG (== BADVERS)
	RCodeBadKey  uint16 = 17
	RCodeBadTime uint16 = 18
)

// RCodeToString returns the canonical mnemonic for rcode, or wraps
// [ErrUnknownRCode] for any unassigned value.
//
// The "BADVERS/SIG" string follows the TypeScript source: rcode 16 is
// shared between EDNS BADVERS and TSIG BADSIG per IANA.
func RCodeToString(rcode uint16) (string, error) {
	switch rcode {
	case RCodeNoError:
		return "NOERROR", nil
	case RCodeFormErr:
		return "FORMERR", nil
	case RCodeServFail:
		return "SERVFAIL", nil
	case RCodeNXDomain:
		return "NXDOMAIN", nil
	case RCodeNotImpl:
		return "NOTIMPL", nil
	case RCodeRefused:
		return "REFUSED", nil
	case RCodeYXDomain:
		return "YXDOMAIN", nil
	case RCodeYXRRSet:
		return "YXRRSET", nil
	case RCodeNXRRSet:
		return "NXRRSET", nil
	case RCodeNotAuth:
		return "NOTAUTH", nil
	case RCodeNotZone:
		return "NOTZONE", nil
	case RCodeBadVers:
		return "BADVERS/SIG", nil
	case RCodeBadKey:
		return "BADKEY", nil
	case RCodeBadTime:
		return "BADTIME", nil
	}
	return "", fmt.Errorf("%w: %d", ErrUnknownRCode, rcode)
}

// StringToRCode is the inverse of [RCodeToString].
func StringToRCode(s string) (uint16, error) {
	switch s {
	case "NOERROR":
		return RCodeNoError, nil
	case "FORMERR":
		return RCodeFormErr, nil
	case "SERVFAIL":
		return RCodeServFail, nil
	case "NXDOMAIN":
		return RCodeNXDomain, nil
	case "NOTIMPL":
		return RCodeNotImpl, nil
	case "REFUSED":
		return RCodeRefused, nil
	case "YXDOMAIN":
		return RCodeYXDomain, nil
	case "YXRRSET":
		return RCodeYXRRSet, nil
	case "NXRRSET":
		return RCodeNXRRSet, nil
	case "NOTAUTH":
		return RCodeNotAuth, nil
	case "NOTZONE":
		return RCodeNotZone, nil
	case "BADVERS/SIG":
		return RCodeBadVers, nil
	case "BADKEY":
		return RCodeBadKey, nil
	case "BADTIME":
		return RCodeBadTime, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownRCode, s)
}
