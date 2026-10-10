package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// tlsaFixedLength is usage(1) + selector(1) + matching type(1).
const tlsaFixedLength = 3

// decodeTLSA writes TLSA / SMIMEA (RFC 6698 §2.2, RFC 8162 §2) as
// `usage selector matching-type hex`. RDATA without certificate data
// has no such form and stays generic.
func decodeTLSA(rdata []byte) string {
	if len(rdata) <= tlsaFixedLength {
		return FormatGenericRData(rdata)
	}
	return fmt.Sprintf("%d %d %d %s", rdata[0], rdata[1], rdata[2], hex.EncodeToString(rdata[tlsaFixedLength:]))
}

// SvcParamKeys with a value format of their own (RFC 9460 §14.3.2).
const (
	svcKeyMandatory     = 0
	svcKeyAlpn          = 1
	svcKeyNoDefaultAlpn = 2
	svcKeyPort          = 3
	svcKeyIPv4Hint      = 4
	svcKeyECH           = 5
	svcKeyIPv6Hint      = 6
)

// svcParamKeyNames are the RFC 9460 §14.3.2 mnemonics, indexed by key.
// zone/svcb.go reads the same names; any other key is keyNNNNN.
var svcParamKeyNames = [...]string{"mandatory", "alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint"}

const (
	svcbMinLength         = 3 // SvcPriority(2) + the root label(1)
	svcParamHeaderLength  = 4 // SvcParamKey(2) + SvcParamValueLength(2)
	svcMandatoryKeyLength = 2
	svcPortLength         = 2
)

// decodeSVCB writes SVCB / HTTPS (RFC 9460 §2.1) as `priority target
// key=value ...`, in the form zone.ParseSVCB reads. RDATA that form
// would not reproduce octet for octet (malformed, keys out of order, a
// target the parser would rewrite, a value with no plain form) stays
// generic, so one bad record does not fail a whole response.
func decodeSVCB(rdata []byte) string {
	if s, ok := svcbPresentation(rdata); ok {
		return s
	}
	return FormatGenericRData(rdata)
}

func svcbPresentation(rdata []byte) (string, bool) {
	if len(rdata) < svcbMinLength {
		return "", false
	}
	target, pos, err := ParseDomainName(rdata, 2)
	if err != nil || !svcbTargetIsPlain(target, rdata[2:pos]) {
		return "", false
	}
	parts := []string{strconv.Itoa(int(binary.BigEndian.Uint16(rdata))), target}
	prevKey := -1
	for pos < len(rdata) {
		if pos+svcParamHeaderLength > len(rdata) {
			return "", false
		}
		key := binary.BigEndian.Uint16(rdata[pos:])
		n := int(binary.BigEndian.Uint16(rdata[pos+2:]))
		pos += svcParamHeaderLength
		if pos+n > len(rdata) || int(key) <= prevKey {
			return "", false
		}
		param, ok := svcParamString(key, rdata[pos:pos+n])
		if !ok {
			return "", false
		}
		prevKey = int(key)
		parts = append(parts, param)
		pos += n
	}
	return strings.Join(parts, " "), true
}

// svcbTargetIsPlain reports whether the parser turns target back into
// raw: it does not follow compression and splits on whitespace. It keeps
// the case of the target (UPSTREAM_FEEDBACK.md UF-008).
func svcbTargetIsPlain(target string, raw []byte) bool {
	if strings.ContainsAny(target, " \t\r\n") {
		return false
	}
	encoded, err := DomainNameToWirePreserveCase(target)
	return err == nil && bytes.Equal(encoded, raw)
}

func svcParamKeyName(key uint16) string {
	if int(key) < len(svcParamKeyNames) {
		return svcParamKeyNames[key]
	}
	return "key" + strconv.Itoa(int(key))
}

// svcParamString writes one SvcParam as `key` or `key=value`. ok is
// false when the parser would not read the result back as v.
func svcParamString(key uint16, v []byte) (string, bool) {
	name := svcParamKeyName(key)
	if key == svcKeyNoDefaultAlpn {
		return name, len(v) == 0
	}
	if len(v) == 0 {
		return name, int(key) >= len(svcParamKeyNames)
	}
	value, ok := svcParamValue(key, v)
	return name + "=" + value, ok
}

func svcParamValue(key uint16, v []byte) (string, bool) {
	switch key {
	case svcKeyMandatory:
		return svcMandatoryValue(v)
	case svcKeyAlpn:
		return svcAlpnValue(v)
	case svcKeyPort:
		if len(v) != svcPortLength {
			return "", false
		}
		return strconv.Itoa(int(binary.BigEndian.Uint16(v))), true
	case svcKeyIPv4Hint:
		return svcAddrValue(v, net.IPv4len)
	case svcKeyECH:
		return base64.StdEncoding.EncodeToString(v), true
	case svcKeyIPv6Hint:
		return svcAddrValue(v, net.IPv6len)
	}
	return hex.EncodeToString(v), true
}

// svcMandatoryValue: comma-separated key names (RFC 9460 §8). The
// parser sorts them, so they must already be in order.
func svcMandatoryValue(v []byte) (string, bool) {
	if len(v)%svcMandatoryKeyLength != 0 {
		return "", false
	}
	names := make([]string, 0, len(v)/svcMandatoryKeyLength)
	prev := -1
	for i := 0; i < len(v); i += svcMandatoryKeyLength {
		key := binary.BigEndian.Uint16(v[i:])
		if int(key) < prev {
			return "", false
		}
		prev = int(key)
		names = append(names, svcParamKeyName(key))
	}
	return strings.Join(names, ","), true
}

// svcAlpnValue: comma-separated ALPN ids (RFC 9460 §7.1.1). The parser
// reads no escapes, so every id must be non-empty printable ASCII
// without `,`, `"` or `\`.
func svcAlpnValue(v []byte) (string, bool) {
	var ids []string
	for pos := 0; pos < len(v); {
		n := int(v[pos])
		pos++
		if n == 0 || pos+n > len(v) {
			return "", false
		}
		id := v[pos : pos+n]
		for _, c := range id {
			if c <= ' ' || c >= 0x7f || c == ',' || c == '"' || c == '\\' {
				return "", false
			}
		}
		ids = append(ids, string(id))
		pos += n
	}
	return strings.Join(ids, ","), true
}

// svcAddrValue: comma-separated addresses of size octets each (RFC 9460
// §7.4). The parser rejects IPv4-mapped IPv6 addresses.
func svcAddrValue(v []byte, size int) (string, bool) {
	if len(v)%size != 0 {
		return "", false
	}
	addrs := make([]string, 0, len(v)/size)
	for i := 0; i < len(v); i += size {
		ip := net.IP(v[i : i+size])
		if size == net.IPv6len && ip.To4() != nil {
			return "", false
		}
		addrs = append(addrs, ip.String())
	}
	return strings.Join(addrs, ","), true
}
