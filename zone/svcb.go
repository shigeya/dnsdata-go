package zone

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/wire"
)

// SVCB is the RR handler for SVCB (RFC 9460 §2, type 64) and HTTPS
// (§9.1, type 65). The two records share the identical wire and
// presentation format byte-for-byte; the same struct backs both.
//
// Wire format (§2.2):
//
//	SvcPriority(2) + TargetName(uncompressed domain) + SvcParams(variable)
//
// SvcParams wire format (§2.2):
//
//	Each: SvcParamKey(2) + SvcParamValueLength(2) + SvcParamValue
//
// Params MUST appear in strictly increasing key order on the wire (§2.2);
// the parser sorts presentation-form params before encoding.
type SVCB struct {
	rr *ResourceRecord

	Priority uint16
	Target   string
	Params   []SvcParam
}

// SvcParam is a single decoded SvcParamKey / SvcParamValue pair. Value
// holds the wire-form octets that follow the key+length header.
type SvcParam struct {
	Key   uint16
	Value []byte
}

// Initial SvcParamKey registry from RFC 9460 §14.3.2.
const (
	SvcKeyMandatory     uint16 = 0
	SvcKeyAlpn          uint16 = 1
	SvcKeyNoDefaultAlpn uint16 = 2
	SvcKeyPort          uint16 = 3
	SvcKeyIPv4Hint      uint16 = 4
	SvcKeyECH           uint16 = 5
	SvcKeyIPv6Hint      uint16 = 6
)

var svcParamKeyMnemonics = map[string]uint16{
	"mandatory":       SvcKeyMandatory,
	"alpn":            SvcKeyAlpn,
	"no-default-alpn": SvcKeyNoDefaultAlpn,
	"port":            SvcKeyPort,
	"ipv4hint":        SvcKeyIPv4Hint,
	"ech":             SvcKeyECH,
	"ipv6hint":        SvcKeyIPv6Hint,
}

var svcKeyNumericRE = regexp.MustCompile(`^key(\d+)$`)

// parseSvcParamKey accepts both registered mnemonics ("alpn") and the
// numeric "keyNNNNN" form for unassigned keys (RFC 9460 §2.1).
func parseSvcParamKey(s string) (uint16, error) {
	lower := strings.ToLower(s)
	if k, ok := svcParamKeyMnemonics[lower]; ok {
		return k, nil
	}
	if m := svcKeyNumericRE.FindStringSubmatch(lower); m != nil {
		n, err := strconv.ParseUint(m[1], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("SvcParamKey %q: %v", s, err)
		}
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unknown SvcParamKey %q", s)
}

// ParseSVCB constructs an SVCB / HTTPS handler from RR presentation form.
// Returns [ErrPresentationFormat] for missing priority/target or invalid
// SvcParam encoding.
func ParseSVCB(rr *ResourceRecord, value string) (*SVCB, error) {
	tokens := strings.Fields(strings.TrimSpace(value))
	if len(tokens) < 2 {
		return nil, fmt.Errorf("%w: SVCB/HTTPS: %q", ErrPresentationFormat, value)
	}
	priority, err := strconv.ParseUint(tokens[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: SVCB priority %q: %v", ErrPresentationFormat, tokens[0], err)
	}
	params, err := parseSvcParams(tokens[2:])
	if err != nil {
		return nil, fmt.Errorf("%w: SVCB params: %v", ErrPresentationFormat, err)
	}
	return &SVCB{
		rr:       rr,
		Priority: uint16(priority),
		Target:   tokens[1],
		Params:   params,
	}, nil
}

// WireBody emits `rdlen(2) + priority(2) + target-wire + svcparams`.
func (s *SVCB) WireBody(b *wire.Builder) error {
	target, err := wire.DomainNameToWire(s.Target)
	if err != nil {
		return fmt.Errorf("%w: SVCB target %q: %v", ErrRDataFormat, s.Target, err)
	}
	paramsLen := 0
	for _, p := range s.Params {
		paramsLen += 4 + len(p.Value)
	}
	b.AppendUint16(uint16(2 + len(target) + paramsLen))
	b.AppendUint16(s.Priority)
	b.AppendBytes(target)
	for _, p := range s.Params {
		b.AppendUint16(p.Key)
		b.AppendUint16(uint16(len(p.Value)))
		b.AppendBytes(p.Value)
	}
	return nil
}

// Clone returns a deep copy of s.
func (s *SVCB) Clone() RecordHandler {
	params := make([]SvcParam, len(s.Params))
	for i, p := range s.Params {
		params[i] = SvcParam{Key: p.Key, Value: append([]byte(nil), p.Value...)}
	}
	return &SVCB{
		rr:       s.rr,
		Priority: s.Priority,
		Target:   s.Target,
		Params:   params,
	}
}

// svcbFactory adapts [ParseSVCB] into [HandlerFactory]. Returns nil on
// parse failure so the zone parser falls back to keeping the value as
// text (TS parity).
func svcbFactory(rr *ResourceRecord, value string) RecordHandler {
	h, err := ParseSVCB(rr, value)
	if err != nil {
		return nil
	}
	return h
}

// httpsFactory reuses svcbFactory; HTTPS (RFC 9460 §9.1) has identical
// wire and presentation format to SVCB.
func httpsFactory(rr *ResourceRecord, value string) RecordHandler {
	return svcbFactory(rr, value)
}

// parseSvcParams decodes a slice of `key[=value]` tokens into a sorted
// SvcParam slice (ascending key, per RFC 9460 §2.2).
func parseSvcParams(tokens []string) ([]SvcParam, error) {
	params := make([]SvcParam, 0, len(tokens))
	for _, tok := range tokens {
		var keyStr, valueStr string
		if eq := strings.IndexByte(tok, '='); eq < 0 {
			keyStr = tok
		} else {
			keyStr = tok[:eq]
			valueStr = tok[eq+1:]
			if len(valueStr) >= 2 && valueStr[0] == '"' && valueStr[len(valueStr)-1] == '"' {
				valueStr = valueStr[1 : len(valueStr)-1]
			}
		}
		key, err := parseSvcParamKey(keyStr)
		if err != nil {
			return nil, err
		}
		val, err := encodeSvcParamValue(key, valueStr)
		if err != nil {
			return nil, err
		}
		params = append(params, SvcParam{Key: key, Value: val})
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Key < params[j].Key })
	return params, nil
}

// encodeSvcParamValue converts a presentation-form SvcParam value into
// its on-the-wire bytes per the key's value-format definition.
func encodeSvcParamValue(key uint16, value string) ([]byte, error) {
	switch key {
	case SvcKeyMandatory:
		return encodeSvcMandatory(value)
	case SvcKeyAlpn:
		return encodeSvcAlpn(value), nil
	case SvcKeyNoDefaultAlpn:
		return nil, nil
	case SvcKeyPort:
		return encodeSvcPort(value)
	case SvcKeyIPv4Hint:
		return encodeSvcIPv4Hint(value)
	case SvcKeyECH:
		// RFC 9460 §7.5: ECH value is base64-encoded in presentation form.
		return base64.StdEncoding.DecodeString(value)
	case SvcKeyIPv6Hint:
		return encodeSvcIPv6Hint(value)
	default:
		// RFC 9460 §2.1: keyNNNNN values arrive as hex octets in
		// presentation form (or any escaped-text form the registry
		// later defines). We honour the hex form to match TS.
		if value == "" {
			return nil, nil
		}
		return hex.DecodeString(value)
	}
}

// encodeSvcMandatory: comma-separated SvcParamKey list in ascending
// uint16 order (RFC 9460 §7.3).
func encodeSvcMandatory(value string) ([]byte, error) {
	parts := strings.Split(value, ",")
	keys := make([]uint16, 0, len(parts))
	for _, p := range parts {
		k, err := parseSvcParamKey(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("mandatory: %v", err)
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]byte, 2*len(keys))
	for i, k := range keys {
		out[2*i] = byte(k >> 8)
		out[2*i+1] = byte(k)
	}
	return out, nil
}

// encodeSvcAlpn: comma-separated ALPN identifiers. Each emits as
// `length(1) + alpn-id` (RFC 9460 §7.1.1).
func encodeSvcAlpn(value string) []byte {
	parts := strings.Split(value, ",")
	out := make([]byte, 0, len(value)+len(parts))
	for _, p := range parts {
		out = append(out, byte(len(p)))
		out = append(out, []byte(p)...)
	}
	return out
}

// encodeSvcPort: single decimal uint16 (RFC 9460 §7.2).
func encodeSvcPort(value string) ([]byte, error) {
	p, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port %q: %v", value, err)
	}
	return []byte{byte(p >> 8), byte(p)}, nil
}

// encodeSvcIPv4Hint: comma-separated dotted-quad IPv4 addresses
// concatenated as 4-byte network-byte-order octets (RFC 9460 §7.4).
func encodeSvcIPv4Hint(value string) ([]byte, error) {
	parts := strings.Split(value, ",")
	out := make([]byte, 0, 4*len(parts))
	for _, p := range parts {
		ip := net.ParseIP(strings.TrimSpace(p))
		if ip == nil {
			return nil, fmt.Errorf("ipv4hint %q: invalid", p)
		}
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("ipv4hint %q: not IPv4", p)
		}
		out = append(out, v4...)
	}
	return out, nil
}

// encodeSvcIPv6Hint: comma-separated IPv6 addresses concatenated as
// 16-byte network-byte-order octets (RFC 9460 §7.4).
func encodeSvcIPv6Hint(value string) ([]byte, error) {
	parts := strings.Split(value, ",")
	out := make([]byte, 0, 16*len(parts))
	for _, p := range parts {
		ip := net.ParseIP(strings.TrimSpace(p))
		if ip == nil {
			return nil, fmt.Errorf("ipv6hint %q: invalid", p)
		}
		v6 := ip.To16()
		if v6 == nil {
			return nil, fmt.Errorf("ipv6hint %q: not IPv6", p)
		}
		if ip.To4() != nil {
			// Reject IPv4 addresses encoded as ::ffff:x.y.z.w — would
			// otherwise sneak through To16(). RFC 9460 expects native
			// IPv6 addresses here.
			return nil, fmt.Errorf("ipv6hint %q: IPv4 mapped, not IPv6", p)
		}
		out = append(out, v6...)
	}
	return out, nil
}
