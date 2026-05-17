package types

import "fmt"

// DNSSEC algorithm numbers per IANA "DNS Security Algorithm Numbers"
// registry (RFC 4034 §A.1, RFC 5702, RFC 5933, RFC 6605, RFC 8080).
//
// This enumeration is not in the dnsdata-js source; it is added in the
// Go port so dnssec_rr.go can refer to algorithms by name. Only the
// algorithms still considered usable today are exposed; deprecated ones
// (DSA, ECC-GOST) are included for round-trip identification.
const (
	AlgoDeleted             uint8 = 0  // RFC 4034 reserved
	AlgoRSAMD5              uint8 = 1  // RFC 2537, deprecated by RFC 6944
	AlgoDH                  uint8 = 2  // RFC 2539
	AlgoDSA                 uint8 = 3  // RFC 2536
	AlgoRSASHA1             uint8 = 5  // RFC 3110
	AlgoDSANSEC3SHA1        uint8 = 6  // RFC 5155
	AlgoRSASHA1NSEC3SHA1    uint8 = 7  // RFC 5155
	AlgoRSASHA256           uint8 = 8  // RFC 5702
	AlgoRSASHA512           uint8 = 10 // RFC 5702
	AlgoECCGOST             uint8 = 12 // RFC 5933, deprecated
	AlgoECDSAP256SHA256     uint8 = 13 // RFC 6605
	AlgoECDSAP384SHA384     uint8 = 14 // RFC 6605
	AlgoED25519             uint8 = 15 // RFC 8080
	AlgoED448               uint8 = 16 // RFC 8080
	AlgoIndirect            uint8 = 252
	AlgoPrivateDNS          uint8 = 253
	AlgoPrivateOID          uint8 = 254
)

// AlgorithmToString returns the canonical mnemonic for a DNSSEC algorithm
// number, or wraps [ErrUnknownAlgo] for any unassigned value.
func AlgorithmToString(a uint8) (string, error) {
	switch a {
	case AlgoDeleted:
		return "DELETE", nil
	case AlgoRSAMD5:
		return "RSAMD5", nil
	case AlgoDH:
		return "DH", nil
	case AlgoDSA:
		return "DSA", nil
	case AlgoRSASHA1:
		return "RSASHA1", nil
	case AlgoDSANSEC3SHA1:
		return "DSA-NSEC3-SHA1", nil
	case AlgoRSASHA1NSEC3SHA1:
		return "RSASHA1-NSEC3-SHA1", nil
	case AlgoRSASHA256:
		return "RSASHA256", nil
	case AlgoRSASHA512:
		return "RSASHA512", nil
	case AlgoECCGOST:
		return "ECC-GOST", nil
	case AlgoECDSAP256SHA256:
		return "ECDSAP256SHA256", nil
	case AlgoECDSAP384SHA384:
		return "ECDSAP384SHA384", nil
	case AlgoED25519:
		return "ED25519", nil
	case AlgoED448:
		return "ED448", nil
	case AlgoIndirect:
		return "INDIRECT", nil
	case AlgoPrivateDNS:
		return "PRIVATEDNS", nil
	case AlgoPrivateOID:
		return "PRIVATEOID", nil
	}
	return "", fmt.Errorf("%w: %d", ErrUnknownAlgo, a)
}

// StringToAlgorithm is the inverse of [AlgorithmToString].
func StringToAlgorithm(s string) (uint8, error) {
	switch s {
	case "DELETE":
		return AlgoDeleted, nil
	case "RSAMD5":
		return AlgoRSAMD5, nil
	case "DH":
		return AlgoDH, nil
	case "DSA":
		return AlgoDSA, nil
	case "RSASHA1":
		return AlgoRSASHA1, nil
	case "DSA-NSEC3-SHA1":
		return AlgoDSANSEC3SHA1, nil
	case "RSASHA1-NSEC3-SHA1":
		return AlgoRSASHA1NSEC3SHA1, nil
	case "RSASHA256":
		return AlgoRSASHA256, nil
	case "RSASHA512":
		return AlgoRSASHA512, nil
	case "ECC-GOST":
		return AlgoECCGOST, nil
	case "ECDSAP256SHA256":
		return AlgoECDSAP256SHA256, nil
	case "ECDSAP384SHA384":
		return AlgoECDSAP384SHA384, nil
	case "ED25519":
		return AlgoED25519, nil
	case "ED448":
		return AlgoED448, nil
	case "INDIRECT":
		return AlgoIndirect, nil
	case "PRIVATEDNS":
		return AlgoPrivateDNS, nil
	case "PRIVATEOID":
		return AlgoPrivateOID, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownAlgo, s)
}

// AlgorithmSupported reports whether the chain validator in this library
// can currently verify signatures made with algorithm a.
//
// Today: RSA (SHA1 / SHA256 / SHA512), ECDSA (P-256 / P-384), and
// Ed25519. Ed448 and the deprecated RSAMD5 / DSA / GOST algorithms are
// recognised by [AlgorithmToString] but not validated.
func AlgorithmSupported(a uint8) bool {
	switch a {
	case AlgoRSASHA1, AlgoRSASHA1NSEC3SHA1,
		AlgoRSASHA256, AlgoRSASHA512,
		AlgoECDSAP256SHA256, AlgoECDSAP384SHA384,
		AlgoED25519:
		return true
	}
	return false
}
