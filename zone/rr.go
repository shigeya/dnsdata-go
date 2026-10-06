package zone

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// HandlerFactory constructs a [RecordHandler] for a given parent record and
// its presentation-form value. Registered through [Registry.Register] or
// [RegisterRRHandler].
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

// ResourceRecord is the textual form of a single DNS RR. The presentation
// value (`Value`) is stored verbatim; structured RDATA is parsed lazily
// by the handler (if any) or by the built-in switch in [ResourceRecord.WireBody].
//
// A ResourceRecord must not be copied after first use (it caches its
// handler); pass it by pointer.
type ResourceRecord struct {
	Label   string
	TTL     uint32
	Class   uint16
	Type    uint16
	Value   string
	handler atomic.Pointer[handlerEntry] // see HandlerFrom
	rdata   []byte                       // the RDATA as received, see NewResourceRecordWithRData
}

// NewResourceRecordWithRData is [NewResourceRecord] for a record read
// off the wire: value is its presentation form and rdata the RDATA
// octets it was decoded from. [ResourceRecord.WireBody] writes rdata
// when no handler or built-in encoder is available for the type, so a
// received record still encodes (and its RRSIG verifies) without the
// zone handlers registered. rdata is copied.
func NewResourceRecordWithRData(label string, ttl uint32, class, rrtype any, value string, rdata []byte) (*ResourceRecord, error) {
	if len(rdata) > maxRDataLength {
		return nil, fmt.Errorf("%w: RDATA length %d", ErrRDataFormat, len(rdata))
	}
	rr, err := NewResourceRecord(label, ttl, class, rrtype, value)
	if err != nil {
		return nil, err
	}
	rr.rdata = append([]byte{}, rdata...)
	return rr, nil
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

// Handler returns the type-specific handler for this RR built by the
// default registry's factory; see [ResourceRecord.HandlerFrom].
func (rr *ResourceRecord) Handler() RecordHandler {
	return rr.HandlerFrom(defaultRegistry)
}

// HandlerFrom returns the type-specific handler for this RR built by
// reg's factory (constructing it on first access), or nil if reg has no
// factory for the type. A nil reg means [DefaultRegistry].
//
// A value in RFC 3597 generic form (`\# <len> <hex>`) is decoded from
// its octets by type, so a known type received as generic RDATA still
// yields its structured handler.
//
// The handler is cached on the record together with the Registry that
// built it, and the cache is only returned to a caller passing that same
// Registry: a record shared between users of different registries (for
// example two Verifiers sharing one cache) never hands one registry's
// handler to the other. The cache holds one entry; alternating
// registries rebuild the handler. Safe for concurrent use.
func (rr *ResourceRecord) HandlerFrom(reg *Registry) RecordHandler {
	reg = reg.orDefault()
	if e := rr.handler.Load(); e != nil && e.reg == reg {
		return e.handler
	}
	f := reg.Lookup(rr.Type)
	if f == nil {
		return nil
	}
	h := rr.buildHandler(f)
	if h == nil {
		return nil
	}
	rr.handler.Store(&handlerEntry{reg: reg, handler: h})
	return h
}

// buildHandler runs factory on the record's value, decoding a generic
// value by type first. Returns nil when the value does not decode.
func (rr *ResourceRecord) buildHandler(factory HandlerFactory) RecordHandler {
	raw, isGeneric, err := rr.GenericRData()
	switch {
	case err != nil:
		return nil
	case isGeneric:
		return handlerFromGeneric(rr, factory, raw)
	default:
		return factory(rr, rr.Value)
	}
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
// A value in RFC 3597 generic form is written verbatim for any type,
// ahead of any handler, so its octets (and hence its canonical form)
// never pass through a re-encoding.
//
// For types without a built-in or registered encoder, a record built
// with [NewResourceRecordWithRData] writes the octets it was received
// as; for any other record the call is a no-op. The fallback serves the
// types whose RDATA holds no compressible or case-folded names (TLSA,
// SMIMEA, SVCB, HTTPS, …), so the received octets are their canonical
// form (RFC 4034 §6.2, RFC 3597 §4); the types that hold such names
// have built-in encoders. Returns [ErrRDataFormat] when an encoder recognises the type but the
// value is malformed, and [ErrPresentationFormat] for malformed generic
// RDATA.
//
// The handler comes from the default registry; [ResourceRecord.WireBodyWith]
// takes the registry explicitly.
func (rr *ResourceRecord) WireBody(b *wire.Builder) error {
	return rr.WireBodyWith(defaultRegistry, b)
}

// WireBodyWith is [ResourceRecord.WireBody] with the handler taken from
// reg (nil means [DefaultRegistry]) through [ResourceRecord.HandlerFrom].
func (rr *ResourceRecord) WireBodyWith(reg *Registry, b *wire.Builder) error {
	raw, isGeneric, err := rr.GenericRData()
	if err != nil {
		return err
	}
	if isGeneric {
		writeWireGeneric(b, raw)
		return nil
	}
	if h := rr.HandlerFrom(reg); h != nil {
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
	if rr.rdata != nil {
		writeWireGeneric(b, rr.rdata)
	}
	return nil
}

// String formats the RR in presentation form: "label ttl class type value".
// Equivalent to TS's to_string().
func (rr *ResourceRecord) String() string {
	return fmt.Sprintf("%s %d %s %s %s", rr.Label, rr.TTL,
		types.RRClassName(rr.Class), types.RRTypeName(rr.Type), rr.Value)
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

var caaRE = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(.*)$`)

// writeWireCAA encodes "<flags> <tag> <value>"; the value is one
// character-string, quoted or bare, with the same escapes as TXT.
func writeWireCAA(b *wire.Builder, value string) error {
	m := caaRE.FindStringSubmatch(value)
	if m == nil {
		return fmt.Errorf("%w: malformed CAA rdata %q", ErrRDataFormat, value)
	}
	flags, _ := strconv.ParseUint(m[1], 10, 8)
	tag := []byte(m[2])
	strs, err := parseTXTValue(m[3])
	if err != nil {
		return err
	}
	if len(strs) != 1 {
		return fmt.Errorf("%w: CAA value is not one character-string: %q", ErrRDataFormat, value)
	}
	val := []byte(strs[0])
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
	strs, err := parseTXTValue(value)
	if err != nil {
		return err
	}
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
// character-strings: quoted strings and bare whitespace-delimited
// tokens, both with RFC 1035 §5.1 escapes (\DDD is one octet, \X is X).
// Matches the TS implementation. A \DDD above 255 is an error.
func parseTXTValue(value string) ([]string, error) {
	var out []string
	i, n := 0, len(value)
	for i < n {
		for i < n && isTXTSpace(value[i]) {
			i++
		}
		if i >= n {
			break
		}
		quoted := value[i] == '"'
		if quoted {
			i++
		}
		var sb strings.Builder
		for i < n {
			c := value[i]
			if (quoted && c == '"') || (!quoted && isTXTSpace(c)) {
				break
			}
			if c != '\\' || i+1 >= n {
				sb.WriteByte(c)
				i++
				continue
			}
			octet, width, err := parseTXTEscape(value[i+1:])
			if err != nil {
				return nil, err
			}
			sb.WriteByte(octet)
			i += 1 + width
		}
		if quoted && i < n {
			i++ // closing quote
		}
		out = append(out, sb.String())
	}
	return out, nil
}

func isTXTSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// parseTXTEscape decodes the escape after a backslash: three decimal
// digits are one octet (\DDD), anything else is taken literally.
// Returns the octet and the number of characters consumed.
func parseTXTEscape(s string) (byte, int, error) {
	if len(s) >= 3 && isDigit(s[0]) && isDigit(s[1]) && isDigit(s[2]) {
		v := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
		if v > 255 {
			return 0, 0, fmt.Errorf("%w: \\%s is not an octet", ErrRDataFormat, s[:3])
		}
		return byte(v), 3, nil
	}
	return s[0], 1, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// firstField returns the first whitespace-delimited token of s, trimmed.
func firstField(s string) string {
	for f := range strings.FieldsSeq(s) {
		return f
	}
	return ""
}
