package wire

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
)

// ErrRData is the umbrella error for [RDataToString] failures.
var ErrRData = errors.New("dns rdata decode")

// RDataToString converts the RDATA section of a resource record into
// its presentation-form value (the right-hand side of a zone-file
// line). The same string is what [zone.NewResourceRecord]'s value
// argument accepts.
//
// msg is the full DNS message; rrtype is the RR-type code; rdata is a
// sub-slice of msg and rdataStart its offset within msg. The
// (msg, rdataStart) pair lets per-type decoders follow compression
// pointers that escape rdata.
//
// Types currently handled: A, AAAA, NS, CNAME, PTR, DNAME, MX, TXT,
// SOA, SRV, CAA, DNSKEY, CDNSKEY, DS, CDS, RRSIG, NSEC, NSEC3,
// NSEC3PARAM. Anything else returns the RFC 3597 §5 unknown-type
// generic form `\# <rdlen> <hex>`.
func RDataToString(msg []byte, rrtype uint16, rdata []byte, rdataStart int) (string, error) {
	switch rrtype {
	case types.TypeA:
		return decodeA(rdata)
	case types.TypeAAAA:
		return decodeAAAA(rdata)
	case types.TypeNS, types.TypeCNAME, types.TypePTR, types.TypeDNAME:
		return decodeSingleName(msg, rdataStart)
	case types.TypeMX:
		return decodeMX(msg, rdata, rdataStart)
	case types.TypeTXT:
		return decodeTXT(rdata)
	case types.TypeSOA:
		return decodeSOA(msg, rdata, rdataStart)
	case types.TypeSRV:
		return decodeSRV(msg, rdata, rdataStart)
	case types.TypeCAA:
		return decodeCAA(rdata)
	case types.TypeDNSKEY, types.TypeCDNSKEY:
		return decodeDNSKEY(rdata)
	case types.TypeDS, types.TypeCDS:
		return decodeDS(rdata)
	case types.TypeRRSIG:
		return decodeRRSIG(msg, rdata, rdataStart)
	case types.TypeNSEC:
		return decodeNSEC(msg, rdata, rdataStart)
	case types.TypeNSEC3:
		return decodeNSEC3(rdata)
	case types.TypeNSEC3PARAM:
		return decodeNSEC3PARAM(rdata)
	}
	return rfc3597(rdata), nil
}

// rfc3597 emits the unknown-type generic form per RFC 3597 §5:
// `\# <rdlen> <hex bytes>`. Spaces separate every two-octet group
// for readability.
func rfc3597(rdata []byte) string {
	var b strings.Builder
	b.WriteString("\\# ")
	b.WriteString(strconv.Itoa(len(rdata)))
	if len(rdata) == 0 {
		return b.String()
	}
	b.WriteByte(' ')
	b.WriteString(hex.EncodeToString(rdata))
	return b.String()
}

func decodeA(rdata []byte) (string, error) {
	if len(rdata) != 4 {
		return "", fmt.Errorf("%w: A rdata length %d, want 4", ErrRData, len(rdata))
	}
	return net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3]).String(), nil
}

func decodeAAAA(rdata []byte) (string, error) {
	if len(rdata) != 16 {
		return "", fmt.Errorf("%w: AAAA rdata length %d, want 16", ErrRData, len(rdata))
	}
	return net.IP(rdata).To16().String(), nil
}

func decodeSingleName(msg []byte, rdataStart int) (string, error) {
	name, _, err := ParseDomainName(msg, rdataStart)
	if err != nil {
		return "", fmt.Errorf("%w: domain name: %v", ErrRData, err)
	}
	return name, nil
}

func decodeMX(msg []byte, rdata []byte, rdataStart int) (string, error) {
	if len(rdata) < 3 {
		return "", fmt.Errorf("%w: MX rdata length %d", ErrRData, len(rdata))
	}
	pref := binary.BigEndian.Uint16(rdata[:2])
	name, _, err := ParseDomainName(msg, rdataStart+2)
	if err != nil {
		return "", fmt.Errorf("%w: MX exchange: %v", ErrRData, err)
	}
	return fmt.Sprintf("%d %s", pref, name), nil
}

func decodeTXT(rdata []byte) (string, error) {
	var parts []string
	pos := 0
	for pos < len(rdata) {
		l := int(rdata[pos])
		pos++
		if pos+l > len(rdata) {
			return "", fmt.Errorf("%w: TXT character-string truncated", ErrRData)
		}
		parts = append(parts, txtQuote(rdata[pos:pos+l]))
		pos += l
	}
	return strings.Join(parts, " "), nil
}

// txtQuote wraps s in double quotes, escaping internal `"` and `\`.
func txtQuote(s []byte) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func decodeSOA(msg []byte, rdata []byte, rdataStart int) (string, error) {
	mname, next, err := ParseDomainName(msg, rdataStart)
	if err != nil {
		return "", fmt.Errorf("%w: SOA mname: %v", ErrRData, err)
	}
	rname, next, err := ParseDomainName(msg, next)
	if err != nil {
		return "", fmt.Errorf("%w: SOA rname: %v", ErrRData, err)
	}
	if next+20 > rdataStart+len(rdata) {
		return "", fmt.Errorf("%w: SOA fixed fields truncated", ErrRData)
	}
	serial := binary.BigEndian.Uint32(msg[next : next+4])
	refresh := binary.BigEndian.Uint32(msg[next+4 : next+8])
	retry := binary.BigEndian.Uint32(msg[next+8 : next+12])
	expire := binary.BigEndian.Uint32(msg[next+12 : next+16])
	minimum := binary.BigEndian.Uint32(msg[next+16 : next+20])
	return fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minimum), nil
}

func decodeSRV(msg []byte, rdata []byte, rdataStart int) (string, error) {
	if len(rdata) < 7 {
		return "", fmt.Errorf("%w: SRV rdata length %d", ErrRData, len(rdata))
	}
	prio := binary.BigEndian.Uint16(rdata[0:2])
	weight := binary.BigEndian.Uint16(rdata[2:4])
	port := binary.BigEndian.Uint16(rdata[4:6])
	target, _, err := ParseDomainName(msg, rdataStart+6)
	if err != nil {
		return "", fmt.Errorf("%w: SRV target: %v", ErrRData, err)
	}
	return fmt.Sprintf("%d %d %d %s", prio, weight, port, target), nil
}

func decodeCAA(rdata []byte) (string, error) {
	if len(rdata) < 2 {
		return "", fmt.Errorf("%w: CAA rdata length %d", ErrRData, len(rdata))
	}
	flags := rdata[0]
	tagLen := int(rdata[1])
	if 2+tagLen > len(rdata) {
		return "", fmt.Errorf("%w: CAA tag truncated", ErrRData)
	}
	tag := string(rdata[2 : 2+tagLen])
	value := rdata[2+tagLen:]
	return fmt.Sprintf("%d %s %q", flags, tag, value), nil
}

func decodeDNSKEY(rdata []byte) (string, error) {
	if len(rdata) < 4 {
		return "", fmt.Errorf("%w: DNSKEY rdata length %d", ErrRData, len(rdata))
	}
	flags := binary.BigEndian.Uint16(rdata[0:2])
	protocol := rdata[2]
	algorithm := rdata[3]
	keyData := rdata[4:]
	return fmt.Sprintf("%d %d %d %s", flags, protocol, algorithm, base64.StdEncoding.EncodeToString(keyData)), nil
}

func decodeDS(rdata []byte) (string, error) {
	if len(rdata) < 4 {
		return "", fmt.Errorf("%w: DS rdata length %d", ErrRData, len(rdata))
	}
	keyTag := binary.BigEndian.Uint16(rdata[0:2])
	algorithm := rdata[2]
	digestType := rdata[3]
	digest := rdata[4:]
	return fmt.Sprintf("%d %d %d %s", keyTag, algorithm, digestType, strings.ToLower(hex.EncodeToString(digest))), nil
}

func decodeRRSIG(msg []byte, rdata []byte, rdataStart int) (string, error) {
	if len(rdata) < 18 {
		return "", fmt.Errorf("%w: RRSIG rdata length %d", ErrRData, len(rdata))
	}
	typeCovered := binary.BigEndian.Uint16(rdata[0:2])
	algorithm := rdata[2]
	labels := rdata[3]
	originalTTL := binary.BigEndian.Uint32(rdata[4:8])
	expire := binary.BigEndian.Uint32(rdata[8:12])
	inception := binary.BigEndian.Uint32(rdata[12:16])
	keyTag := binary.BigEndian.Uint16(rdata[16:18])

	signer, next, err := ParseDomainName(msg, rdataStart+18)
	if err != nil {
		return "", fmt.Errorf("%w: RRSIG signer: %v", ErrRData, err)
	}
	if next > rdataStart+len(rdata) {
		return "", fmt.Errorf("%w: RRSIG signer extends past rdata", ErrRData)
	}
	signature := msg[next : rdataStart+len(rdata)]

	typeName, err := types.RRTypeToString(typeCovered)
	if err != nil {
		typeName = fmt.Sprintf("TYPE%d", typeCovered)
	}
	return fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
		typeName, algorithm, labels, originalTTL, expire, inception, keyTag, signer,
		base64.StdEncoding.EncodeToString(signature)), nil
}

func decodeNSEC(msg []byte, rdata []byte, rdataStart int) (string, error) {
	nextDomain, next, err := ParseDomainName(msg, rdataStart)
	if err != nil {
		return "", fmt.Errorf("%w: NSEC next: %v", ErrRData, err)
	}
	bitmap := msg[next : rdataStart+len(rdata)]
	bitmapTypes, err := decodeBitmap(bitmap)
	if err != nil {
		return "", fmt.Errorf("%w: NSEC bitmap: %v", ErrRData, err)
	}
	parts := []string{nextDomain}
	for _, t := range bitmapTypes {
		name, err := types.RRTypeToString(t)
		if err != nil {
			name = fmt.Sprintf("TYPE%d", t)
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, " "), nil
}

func decodeNSEC3(rdata []byte) (string, error) {
	if len(rdata) < 5 {
		return "", fmt.Errorf("%w: NSEC3 rdata length %d", ErrRData, len(rdata))
	}
	hashAlgo := rdata[0]
	flags := rdata[1]
	iterations := binary.BigEndian.Uint16(rdata[2:4])
	saltLen := int(rdata[4])
	pos := 5
	if pos+saltLen > len(rdata) {
		return "", fmt.Errorf("%w: NSEC3 salt truncated", ErrRData)
	}
	salt := rdata[pos : pos+saltLen]
	pos += saltLen
	if pos+1 > len(rdata) {
		return "", fmt.Errorf("%w: NSEC3 next-hash length missing", ErrRData)
	}
	nextLen := int(rdata[pos])
	pos++
	if pos+nextLen > len(rdata) {
		return "", fmt.Errorf("%w: NSEC3 next-hash truncated", ErrRData)
	}
	nextHash := rdata[pos : pos+nextLen]
	pos += nextLen
	bitmap := rdata[pos:]
	bitmapTypes, err := decodeBitmap(bitmap)
	if err != nil {
		return "", fmt.Errorf("%w: NSEC3 bitmap: %v", ErrRData, err)
	}
	saltStr := "-"
	if len(salt) > 0 {
		saltStr = strings.ToUpper(hex.EncodeToString(salt))
	}
	parts := []string{
		strconv.Itoa(int(hashAlgo)),
		strconv.Itoa(int(flags)),
		strconv.Itoa(int(iterations)),
		saltStr,
		base32hexEncode(nextHash),
	}
	for _, t := range bitmapTypes {
		name, err := types.RRTypeToString(t)
		if err != nil {
			name = fmt.Sprintf("TYPE%d", t)
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, " "), nil
}

func decodeNSEC3PARAM(rdata []byte) (string, error) {
	if len(rdata) < 5 {
		return "", fmt.Errorf("%w: NSEC3PARAM rdata length %d", ErrRData, len(rdata))
	}
	hashAlgo := rdata[0]
	flags := rdata[1]
	iterations := binary.BigEndian.Uint16(rdata[2:4])
	saltLen := int(rdata[4])
	if 5+saltLen > len(rdata) {
		return "", fmt.Errorf("%w: NSEC3PARAM salt truncated", ErrRData)
	}
	salt := rdata[5 : 5+saltLen]
	saltStr := "-"
	if len(salt) > 0 {
		saltStr = strings.ToUpper(hex.EncodeToString(salt))
	}
	return fmt.Sprintf("%d %d %d %s", hashAlgo, flags, iterations, saltStr), nil
}

// decodeBitmap re-implements the RFC 4034 §4.1.2 bitmap decoder in
// wire/. dnssec.DecodeTypeBitmap does the same thing but importing
// dnssec from wire creates a dependency cycle. Keep this short and
// stand-alone.
func decodeBitmap(bitmap []byte) ([]uint16, error) {
	var out []uint16
	pos := 0
	for pos < len(bitmap) {
		if pos+2 > len(bitmap) {
			return nil, errors.New("window header truncated")
		}
		window := bitmap[pos]
		length := int(bitmap[pos+1])
		pos += 2
		if length == 0 || length > 32 {
			return nil, fmt.Errorf("window length %d", length)
		}
		if pos+length > len(bitmap) {
			return nil, errors.New("window data truncated")
		}
		for i := 0; i < length; i++ {
			byteVal := bitmap[pos+i]
			for bit := 0; bit < 8; bit++ {
				if byteVal&(0x80>>bit) != 0 {
					out = append(out, uint16(window)<<8|uint16(i*8+bit))
				}
			}
		}
		pos += length
	}
	return out, nil
}

// base32hexEncode is the inverse of dnssec.base32hexDecode. RFC 4648
// "Base 32 with Extended Hex Alphabet" — used by NSEC3 owner labels.
func base32hexEncode(b []byte) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	if len(b) == 0 {
		return ""
	}
	var bits []byte
	for _, c := range b {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (c>>uint(i))&1)
		}
	}
	for len(bits)%5 != 0 {
		bits = append(bits, 0)
	}
	var out strings.Builder
	for i := 0; i < len(bits); i += 5 {
		var v byte
		for j := 0; j < 5; j++ {
			v = v<<1 | bits[i+j]
		}
		out.WriteByte(alphabet[v])
	}
	return out.String()
}
