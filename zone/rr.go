package zone

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// HandlerFactory constructs a [RecordHandler] for a given parent record and
// its presentation-form value. Registered through [RegisterRRHandler].
type HandlerFactory func(rr *ResourceRecord, value string) RecordHandler

// RecordHandler is the abstract data handler for a single RR type. Each
// concrete handler knows how to serialise its RDATA into wire form.
//
// The Go port replaces TypeScript's `abstract class` and getter chain with
// a small interface: handlers delegate label / ttl / type / class / value
// to the parent ResourceRecord rather than re-exposing them, so callers
// usually only touch [WireBody] and [Clone].
type RecordHandler interface {
	// WireBody appends `rdlength(uint16) + rdata` for this record to b.
	WireBody(b *wire.Builder) error
	// Clone returns a deep copy of the handler detached from any
	// parent record (used by tests and by zone-walking helpers).
	Clone() RecordHandler
}

// Registry stores RR-type handler factories keyed by [types.Type*] code.
// Used by dnssec_rr.go (future) to plug DNSKEY / RRSIG / DS / NSEC /
// NSEC3 handlers without modifying this package.
//
// The registry is package-global to match dnsdata-js's
// register_rr_handler shape. If future requirements demand isolation,
// switch to a per-[Zone] registry; see UPSTREAM_FEEDBACK / DESIGN.md.
var (
	registryMu sync.RWMutex
	registry   = map[uint16]HandlerFactory{}
)

// RegisterRRHandler installs factory as the handler builder for RRs of
// the given type. Subsequent calls overwrite earlier ones.
func RegisterRRHandler(rrtype uint16, factory HandlerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[rrtype] = factory
}

// lookupRRHandler is the read side of the registry.
func lookupRRHandler(rrtype uint16) HandlerFactory {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[rrtype]
}

// ResourceRecord is the textual form of a single DNS RR. The presentation
// value (`Value`) is stored verbatim; structured RDATA is parsed lazily
// by the handler (if any) or by the built-in switch in [ResourceRecord.WireBody].
type ResourceRecord struct {
	Label   string
	TTL     uint32
	Class   uint16
	Type    uint16
	Value   string
	handler RecordHandler
}

// NewResourceRecord constructs an RR from its textual fields. class and
// rrtype may be either numeric ([types.ClassIN], [types.TypeA], …) or
// their mnemonic strings ("IN", "A", …).
//
// Returns [ErrPresentationFormat] if a mnemonic class or type is unknown.
func NewResourceRecord(label string, ttl uint32, class, rrtype any, value string) (*ResourceRecord, error) {
	c, err := coerceClass(class)
	if err != nil {
		return nil, err
	}
	t, err := coerceType(rrtype)
	if err != nil {
		return nil, err
	}
	return &ResourceRecord{
		Label: label,
		TTL:   ttl,
		Class: c,
		Type:  t,
		Value: value,
	}, nil
}

func coerceClass(v any) (uint16, error) {
	switch x := v.(type) {
	case string:
		c, err := types.StringToRRClass(x)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrPresentationFormat, err)
		}
		return c, nil
	case uint16:
		return x, nil
	case int:
		return uint16(x), nil
	}
	return 0, fmt.Errorf("%w: unsupported class type %T", ErrPresentationFormat, v)
}

func coerceType(v any) (uint16, error) {
	switch x := v.(type) {
	case string:
		t, err := types.StringToRRType(x)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrPresentationFormat, err)
		}
		return t, nil
	case uint16:
		return x, nil
	case int:
		return uint16(x), nil
	}
	return 0, fmt.Errorf("%w: unsupported type %T", ErrPresentationFormat, v)
}

// Handler returns the type-specific handler for this RR (constructing it
// on first access via the registered factory), or nil if no factory is
// registered for the type. Result is cached on the record.
func (rr *ResourceRecord) Handler() RecordHandler {
	if rr.handler != nil {
		return rr.handler
	}
	if f := lookupRRHandler(rr.Type); f != nil {
		rr.handler = f(rr, rr.Value)
	}
	return rr.handler
}

// WireHeader appends `owner_name(wire) + type(uint16) + class(uint16)` to b.
//
// Returns an error only if domain-name encoding fails (e.g. an oversized
// label or name).
func (rr *ResourceRecord) WireHeader(b *wire.Builder) error {
	name, err := wire.DomainNameToWire(rr.Label)
	if err != nil {
		return err
	}
	b.AppendBytes(name)
	b.AppendUint16(rr.Type)
	b.AppendUint16(rr.Class)
	return nil
}

// WireBody appends `rdlength(uint16) + rdata` to b. If a registered
// handler exists it is delegated to; otherwise the built-in encoders for
// A / NS / CNAME / SOA / PTR / DNAME / MX / TXT / AAAA / SRV / CAA are used.
//
// For types without a built-in or registered encoder the call is a no-op.
// Returns [ErrRDataFormat] when an encoder recognises the type but the
// value is malformed.
func (rr *ResourceRecord) WireBody(b *wire.Builder) error {
	if h := rr.Handler(); h != nil {
		return h.WireBody(b)
	}
	switch rr.Type {
	case types.TypeA:
		return writeWireA(b, rr.Value)
	case types.TypeNS, types.TypeCNAME, types.TypePTR, types.TypeDNAME:
		return writeWireSingleName(b, rr.Value)
	case types.TypeSOA:
		return writeWireSOA(b, rr.Value)
	case types.TypeMX:
		return writeWireMX(b, rr.Value)
	case types.TypeTXT:
		return writeWireTXT(b, rr.Value)
	case types.TypeAAAA:
		return writeWireAAAA(b, rr.Value)
	case types.TypeSRV:
		return writeWireSRV(b, rr.Value)
	case types.TypeCAA:
		return writeWireCAA(b, rr.Value)
	}
	return nil
}

// String formats the RR in presentation form: "label ttl class type value".
// Equivalent to TS's to_string().
func (rr *ResourceRecord) String() string {
	className, err := types.RRClassToString(rr.Class)
	if err != nil {
		className = fmt.Sprintf("CLASS%d", rr.Class)
	}
	typeName, err := types.RRTypeToString(rr.Type)
	if err != nil {
		typeName = fmt.Sprintf("TYPE%d", rr.Type)
	}
	return fmt.Sprintf("%s %d %s %s %s", rr.Label, rr.TTL, className, typeName, rr.Value)
}

// --------------------------------------------------------------------
// Built-in RDATA encoders.
// --------------------------------------------------------------------

func writeWireA(b *wire.Builder, value string) error {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return fmt.Errorf("%w: invalid A address %q", ErrRDataFormat, value)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("%w: not an IPv4 address %q", ErrRDataFormat, value)
	}
	b.AppendUint16(4)
	b.AppendBytes(v4)
	return nil
}

func writeWireAAAA(b *wire.Builder, value string) error {
	field := firstField(value)
	ip := net.ParseIP(field)
	if ip == nil || ip.To4() != nil {
		// To4() != nil means this is a 4-byte IPv4, not an IPv6.
		return fmt.Errorf("%w: invalid AAAA address %q", ErrRDataFormat, value)
	}
	v6 := ip.To16()
	if v6 == nil {
		return fmt.Errorf("%w: not an IPv6 address %q", ErrRDataFormat, value)
	}
	b.AppendUint16(16)
	b.AppendBytes(v6)
	return nil
}

// writeWireSingleName encodes the wire form of an RR whose RDATA is a
// single uncompressed domain name: NS / CNAME / PTR / DNAME (RFC 1035
// §§3.3.11, 3.3.1, 3.3.12 and RFC 6672 §2.1, all the same shape).
func writeWireSingleName(b *wire.Builder, value string) error {
	name := firstField(value)
	if name == "" {
		return fmt.Errorf("%w: missing domain name", ErrRDataFormat)
	}
	wn, err := wire.DomainNameToWire(name)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRDataFormat, err)
	}
	b.AppendUint16(uint16(len(wn)))
	b.AppendBytes(wn)
	return nil
}

var soaRE = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)`)

func writeWireSOA(b *wire.Builder, value string) error {
	m := soaRE.FindStringSubmatch(value)
	if m == nil {
		return fmt.Errorf("%w: malformed SOA rdata %q", ErrRDataFormat, value)
	}
	mname, err := wire.DomainNameToWire(m[1])
	if err != nil {
		return fmt.Errorf("%w: SOA mname: %v", ErrRDataFormat, err)
	}
	rname, err := wire.DomainNameToWire(m[2])
	if err != nil {
		return fmt.Errorf("%w: SOA rname: %v", ErrRDataFormat, err)
	}
	serial, _ := strconv.ParseUint(m[3], 10, 32)
	refresh, _ := strconv.ParseUint(m[4], 10, 32)
	retry, _ := strconv.ParseUint(m[5], 10, 32)
	expire, _ := strconv.ParseUint(m[6], 10, 32)
	minimum, _ := strconv.ParseUint(m[7], 10, 32)
	rdlen := len(mname) + len(rname) + 4*5
	b.AppendUint16(uint16(rdlen))
	b.AppendBytes(mname)
	b.AppendBytes(rname)
	b.AppendUint32(uint32(serial))
	b.AppendUint32(uint32(refresh))
	b.AppendUint32(uint32(retry))
	b.AppendUint32(uint32(expire))
	b.AppendUint32(uint32(minimum))
	return nil
}

var mxRE = regexp.MustCompile(`^(\d+)\s+(\S+)`)

func writeWireMX(b *wire.Builder, value string) error {
	m := mxRE.FindStringSubmatch(value)
	if m == nil {
		return fmt.Errorf("%w: malformed MX rdata %q", ErrRDataFormat, value)
	}
	pref, _ := strconv.ParseUint(m[1], 10, 16)
	exch, err := wire.DomainNameToWire(m[2])
	if err != nil {
		return fmt.Errorf("%w: MX exchange: %v", ErrRDataFormat, err)
	}
	b.AppendUint16(uint16(2 + len(exch)))
	b.AppendUint16(uint16(pref))
	b.AppendBytes(exch)
	return nil
}

var srvRE = regexp.MustCompile(`^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)`)

func writeWireSRV(b *wire.Builder, value string) error {
	m := srvRE.FindStringSubmatch(value)
	if m == nil {
		return fmt.Errorf("%w: malformed SRV rdata %q", ErrRDataFormat, value)
	}
	prio, _ := strconv.ParseUint(m[1], 10, 16)
	wt, _ := strconv.ParseUint(m[2], 10, 16)
	port, _ := strconv.ParseUint(m[3], 10, 16)
	target, err := wire.DomainNameToWire(m[4])
	if err != nil {
		return fmt.Errorf("%w: SRV target: %v", ErrRDataFormat, err)
	}
	b.AppendUint16(uint16(6 + len(target)))
	b.AppendUint16(uint16(prio))
	b.AppendUint16(uint16(wt))
	b.AppendUint16(uint16(port))
	b.AppendBytes(target)
	return nil
}

var caaRE = regexp.MustCompile(`^(\d+)\s+(\S+)\s+"([^"]*)"`)

func writeWireCAA(b *wire.Builder, value string) error {
	m := caaRE.FindStringSubmatch(value)
	if m == nil {
		return fmt.Errorf("%w: malformed CAA rdata %q", ErrRDataFormat, value)
	}
	flags, _ := strconv.ParseUint(m[1], 10, 8)
	tag := []byte(m[2])
	val := []byte(m[3])
	b.AppendUint16(uint16(2 + len(tag) + len(val)))
	b.AppendUint8(uint8(flags))
	b.AppendUint8(uint8(len(tag)))
	b.AppendBytes(tag)
	b.AppendBytes(val)
	return nil
}

// writeWireTXT encodes one or more character-strings, each prefixed by a
// length byte and broken at 255-byte boundaries. Matches RFC 1035 §3.3.14.
func writeWireTXT(b *wire.Builder, value string) error {
	strs := parseTXTValue(value)
	type chunk struct{ body []byte }
	var chunks []chunk
	total := 0
	emit := func(p []byte) {
		chunks = append(chunks, chunk{body: p})
		total += 1 + len(p)
	}
	if len(strs) == 0 {
		emit(nil)
	}
	for _, s := range strs {
		bs := []byte(s)
		if len(bs) == 0 {
			emit(nil)
			continue
		}
		for off := 0; off < len(bs); off += 255 {
			end := min(off+255, len(bs))
			emit(bs[off:end])
		}
	}
	b.AppendUint16(uint16(total))
	for _, c := range chunks {
		b.AppendUint8(uint8(len(c.body)))
		b.AppendBytes(c.body)
	}
	return nil
}

// parseTXTValue tokenises a TXT presentation value into individual
// character-strings. Supports quoted strings with `\` escapes and bare
// whitespace-delimited tokens — matches the TS implementation.
func parseTXTValue(value string) []string {
	var out []string
	i, n := 0, len(value)
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	for i < n {
		for i < n && isSpace(value[i]) {
			i++
		}
		if i >= n {
			break
		}
		if value[i] == '"' {
			i++
			var sb strings.Builder
			for i < n && value[i] != '"' {
				if value[i] == '\\' && i+1 < n {
					i++
					sb.WriteByte(value[i])
				} else {
					sb.WriteByte(value[i])
				}
				i++
			}
			if i < n {
				i++ // closing quote
			}
			out = append(out, sb.String())
		} else {
			var sb strings.Builder
			for i < n && !isSpace(value[i]) {
				sb.WriteByte(value[i])
				i++
			}
			out = append(out, sb.String())
		}
	}
	return out
}

// firstField returns the first whitespace-delimited token of s, trimmed.
func firstField(s string) string {
	for f := range strings.FieldsSeq(s) {
		return f
	}
	return ""
}
