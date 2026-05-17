package types

import "fmt"

// RR type constants per IANA "Resource Record (RR) TYPEs" registry.
// Only the types actually handled by the TypeScript source are exposed;
// the remainder are commented out in the source-of-truth port and can be
// enabled when needed.
const (
	TypeInvalid    uint16 = 0
	TypeA          uint16 = 1
	TypeNS         uint16 = 2
	TypeCNAME      uint16 = 5
	TypeSOA        uint16 = 6
	TypePTR        uint16 = 12
	TypeHINFO      uint16 = 13
	TypeMX         uint16 = 15
	TypeTXT        uint16 = 16
	TypeRP         uint16 = 17
	TypeAAAA       uint16 = 28
	TypeLOC        uint16 = 29
	TypeSRV        uint16 = 33
	TypeNAPTR      uint16 = 35
	TypeCERT       uint16 = 37
	TypeDNAME      uint16 = 39
	TypeOPT        uint16 = 41
	TypeDS         uint16 = 43
	TypeSSHFP      uint16 = 44
	TypeRRSIG      uint16 = 46
	TypeNSEC       uint16 = 47
	TypeDNSKEY     uint16 = 48
	TypeNSEC3      uint16 = 50
	TypeNSEC3PARAM uint16 = 51
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeCDS        uint16 = 59
	TypeCDNSKEY    uint16 = 60
	TypeOPENPGPKEY uint16 = 61
	TypeCSYNC      uint16 = 62
	TypeSVCB       uint16 = 64
	TypeHTTPS      uint16 = 65
	TypeEUI48      uint16 = 108
	TypeEUI64      uint16 = 109
	TypeURI        uint16 = 256
	TypeCAA        uint16 = 257
)

// RRTypeToString returns the canonical mnemonic for an RR type code, or
// wraps [ErrUnknownRRType] for any unassigned value.
func RRTypeToString(t uint16) (string, error) {
	switch t {
	case TypeInvalid:
		return "INVALID", nil
	case TypeA:
		return "A", nil
	case TypeNS:
		return "NS", nil
	case TypeCNAME:
		return "CNAME", nil
	case TypeSOA:
		return "SOA", nil
	case TypePTR:
		return "PTR", nil
	case TypeHINFO:
		return "HINFO", nil
	case TypeMX:
		return "MX", nil
	case TypeTXT:
		return "TXT", nil
	case TypeRP:
		return "RP", nil
	case TypeAAAA:
		return "AAAA", nil
	case TypeLOC:
		return "LOC", nil
	case TypeSRV:
		return "SRV", nil
	case TypeNAPTR:
		return "NAPTR", nil
	case TypeCERT:
		return "CERT", nil
	case TypeDNAME:
		return "DNAME", nil
	case TypeOPT:
		return "OPT", nil
	case TypeDS:
		return "DS", nil
	case TypeSSHFP:
		return "SSHFP", nil
	case TypeRRSIG:
		return "RRSIG", nil
	case TypeNSEC:
		return "NSEC", nil
	case TypeDNSKEY:
		return "DNSKEY", nil
	case TypeNSEC3:
		return "NSEC3", nil
	case TypeNSEC3PARAM:
		return "NSEC3PARAM", nil
	case TypeTLSA:
		return "TLSA", nil
	case TypeSMIMEA:
		return "SMIMEA", nil
	case TypeCDS:
		return "CDS", nil
	case TypeCDNSKEY:
		return "CDNSKEY", nil
	case TypeOPENPGPKEY:
		return "OPENPGPKEY", nil
	case TypeCSYNC:
		return "CSYNC", nil
	case TypeSVCB:
		return "SVCB", nil
	case TypeHTTPS:
		return "HTTPS", nil
	case TypeEUI48:
		return "EUI48", nil
	case TypeEUI64:
		return "EUI64", nil
	case TypeURI:
		return "URI", nil
	case TypeCAA:
		return "CAA", nil
	}
	return "", fmt.Errorf("%w: %d", ErrUnknownRRType, t)
}

// StringToRRType is the inverse of [RRTypeToString].
func StringToRRType(s string) (uint16, error) {
	switch s {
	case "INVALID":
		return TypeInvalid, nil
	case "A":
		return TypeA, nil
	case "NS":
		return TypeNS, nil
	case "CNAME":
		return TypeCNAME, nil
	case "SOA":
		return TypeSOA, nil
	case "PTR":
		return TypePTR, nil
	case "HINFO":
		return TypeHINFO, nil
	case "MX":
		return TypeMX, nil
	case "TXT":
		return TypeTXT, nil
	case "RP":
		return TypeRP, nil
	case "AAAA":
		return TypeAAAA, nil
	case "LOC":
		return TypeLOC, nil
	case "SRV":
		return TypeSRV, nil
	case "NAPTR":
		return TypeNAPTR, nil
	case "CERT":
		return TypeCERT, nil
	case "DNAME":
		return TypeDNAME, nil
	case "OPT":
		return TypeOPT, nil
	case "DS":
		return TypeDS, nil
	case "SSHFP":
		return TypeSSHFP, nil
	case "RRSIG":
		return TypeRRSIG, nil
	case "NSEC":
		return TypeNSEC, nil
	case "DNSKEY":
		return TypeDNSKEY, nil
	case "NSEC3":
		return TypeNSEC3, nil
	case "NSEC3PARAM":
		return TypeNSEC3PARAM, nil
	case "TLSA":
		return TypeTLSA, nil
	case "SMIMEA":
		return TypeSMIMEA, nil
	case "CDS":
		return TypeCDS, nil
	case "CDNSKEY":
		return TypeCDNSKEY, nil
	case "OPENPGPKEY":
		return TypeOPENPGPKEY, nil
	case "CSYNC":
		return TypeCSYNC, nil
	case "SVCB":
		return TypeSVCB, nil
	case "HTTPS":
		return TypeHTTPS, nil
	case "EUI48":
		return TypeEUI48, nil
	case "EUI64":
		return TypeEUI64, nil
	case "URI":
		return TypeURI, nil
	case "CAA":
		return TypeCAA, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownRRType, s)
}

// QTypeValidForRequest reports whether t is acceptable in the qtype field
// of a DNS request. Meta-types (OPT) and obsolete types return false.
func QTypeValidForRequest(t uint16) bool {
	switch t {
	case TypeA, TypeNS, TypeCNAME, TypeSOA, TypePTR, TypeHINFO,
		TypeMX, TypeTXT, TypeRP, TypeAAAA, TypeLOC,
		TypeSRV, TypeNAPTR, TypeCERT, TypeDNAME,
		TypeDS, TypeSSHFP, TypeRRSIG, TypeNSEC, TypeDNSKEY,
		TypeNSEC3, TypeNSEC3PARAM, TypeTLSA, TypeSMIMEA,
		TypeCDS, TypeCDNSKEY, TypeOPENPGPKEY, TypeCSYNC,
		TypeSVCB, TypeHTTPS, TypeEUI48, TypeEUI64, TypeURI:
		return true
	}
	return false
}
