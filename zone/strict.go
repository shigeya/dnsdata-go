package zone

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// ParseError reports a master-file line that [Zone.ReadStringStrict]
// rejected. Line is the 1-based number of the first physical line of
// the record (a parenthesised record may span several). Err wraps
// [ErrPresentationFormat] or [ErrRDataFormat].
type ParseError struct {
	Line int
	Text string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("zone line %d: %v", e.Line, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// ReadStringStrict parses RFC 1035 master-file text like [Zone.ReadString]
// but rejects, instead of skipping, anything it cannot turn into a
// record: unknown types or classes, relative owners without `$ORIGIN`,
// records without a TTL, malformed RDATA (including RFC 3597 generic
// RDATA whose length does not match), types with no encoder, and
// unsupported directives such as `$INCLUDE`.
//
// Every record is encoded once as a check, so a value that would
// otherwise encode to nothing is caught here. The zone is only modified
// when the whole text parses; on error it is left untouched and a
// [*ParseError] is returned.
//
// Differences from ReadString: `;` inside a quoted string is data, the
// class may be any mnemonic or `CLASS<n>`, and TTL and class may appear
// in either order. Domain names inside RDATA are not qualified with
// `$ORIGIN`; write them fully qualified.
func (z *Zone) ReadStringStrict(text string) error {
	lines, err := strictLogicalLines(text)
	if err != nil {
		return err
	}
	st := strictState{}
	var parsed []*ResourceRecord
	for _, ll := range lines {
		rr, err := st.parse(ll)
		if err != nil {
			return &ParseError{Line: ll.num, Text: ll.text, Err: err}
		}
		if rr != nil {
			parsed = append(parsed, rr)
		}
	}
	for _, rr := range parsed {
		z.AddRR(rr)
	}
	return nil
}

// logicalLine is one record or directive after comment removal and
// parenthesis joining.
type logicalLine struct {
	num      int    // first physical line, 1-based
	text     string // joined text, parentheses removed, trimmed
	inherits bool   // first physical line starts with a blank: owner is inherited
}

// strictLogicalLines strips comments and joins parenthesised
// continuations. Quotes protect `;`, `(` and `)`.
func strictLogicalLines(text string) ([]logicalLine, error) {
	var out []logicalLine
	var cur *logicalLine
	depth := 0
	for i, raw := range strings.Split(text, "\n") {
		body, d, err := stripStrictLine(raw, depth)
		if err != nil {
			return nil, &ParseError{Line: i + 1, Text: raw, Err: err}
		}
		depth = d
		if cur == nil {
			if strings.TrimSpace(body) == "" {
				continue
			}
			cur = &logicalLine{num: i + 1, inherits: raw[0] == ' ' || raw[0] == '\t'}
		}
		cur.text += " " + body
		if depth == 0 {
			cur.text = strings.TrimSpace(cur.text)
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		return nil, &ParseError{Line: cur.num, Text: cur.text,
			Err: fmt.Errorf("%w: unclosed parenthesis", ErrPresentationFormat)}
	}
	return out, nil
}

// stripStrictLine removes a trailing comment and the parentheses from
// one physical line, returning the new parenthesis depth.
func stripStrictLine(line string, depth int) (string, int, error) {
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line):
			b.WriteByte(c)
			i++
			c = line[i]
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == ';':
			return b.String(), depth, nil
		case c == '(' || c == ')':
			if c == '(' {
				depth++
			} else if depth--; depth < 0 {
				return "", 0, fmt.Errorf("%w: unbalanced ')'", ErrPresentationFormat)
			}
			c = ' '
		}
		b.WriteByte(c)
	}
	return b.String(), depth, nil
}

// strictState carries the directives and inherited owner across lines.
type strictState struct {
	origin     string
	defaultTTL uint32
	hasTTL     bool
	prevOwner  string
}

// parse handles one logical line. It returns a nil record for a
// directive.
func (st *strictState) parse(ll logicalLine) (*ResourceRecord, error) {
	if !ll.inherits && strings.HasPrefix(ll.text, "$") {
		return nil, st.directive(ll.text)
	}
	spans := fieldSpans(ll.text)
	owner := st.prevOwner
	if !ll.inherits {
		o, err := st.qualify(ll.text[spans[0][0]:spans[0][1]])
		if err != nil {
			return nil, err
		}
		owner, spans = o, spans[1:]
	}
	if owner == "" {
		return nil, fmt.Errorf("%w: no owner to inherit", ErrPresentationFormat)
	}
	rr, err := st.record(owner, ll.text, spans)
	if err != nil {
		return nil, err
	}
	st.prevOwner = owner
	return rr, nil
}

func (st *strictState) directive(text string) error {
	fields := strings.Fields(text)
	switch strings.ToUpper(fields[0]) {
	case "$ORIGIN":
		if len(fields) != 2 || !strings.HasSuffix(fields[1], ".") {
			return fmt.Errorf("%w: $ORIGIN needs one absolute name", ErrPresentationFormat)
		}
		st.origin = fields[1]
		return nil
	case "$TTL":
		if len(fields) != 2 {
			return fmt.Errorf("%w: $TTL needs one value", ErrPresentationFormat)
		}
		ttl, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return fmt.Errorf("%w: $TTL %q", ErrPresentationFormat, fields[1])
		}
		st.defaultTTL, st.hasTTL = uint32(ttl), true
		return nil
	}
	return fmt.Errorf("%w: unsupported directive %s", ErrPresentationFormat, fields[0])
}

// qualify turns an owner token into an absolute name and checks that
// it encodes.
func (st *strictState) qualify(name string) (string, error) {
	switch {
	case name == "@":
		if st.origin == "" {
			return "", fmt.Errorf("%w: @ without $ORIGIN", ErrPresentationFormat)
		}
		name = st.origin
	case strings.HasSuffix(name, "."):
	case st.origin == "":
		return "", fmt.Errorf("%w: relative owner %q without $ORIGIN", ErrPresentationFormat, name)
	case st.origin == ".":
		name += "."
	default:
		name += "." + st.origin
	}
	if name != "." && slices.Contains(strings.Split(strings.TrimSuffix(name, "."), "."), "") {
		return "", fmt.Errorf("%w: owner %q has an empty label", ErrPresentationFormat, name)
	}
	if _, err := wire.DomainNameToWire(name); err != nil {
		return "", fmt.Errorf("%w: owner %q: %v", ErrPresentationFormat, name, err)
	}
	return name, nil
}

// record parses `[ttl] [class] type rdata` (TTL and class in either
// order) from the fields at spans and checks that the result encodes.
func (st *strictState) record(owner, text string, spans [][2]int) (*ResourceRecord, error) {
	ttl, hasTTL := st.defaultTTL, st.hasTTL
	class := types.ClassIN
	i := 0
	for ; i < len(spans) && i < 2; i++ {
		tok := text[spans[i][0]:spans[i][1]]
		if n, err := strconv.ParseUint(tok, 10, 32); err == nil {
			ttl, hasTTL = uint32(n), true
			continue
		}
		c, err := types.StringToRRClass(tok)
		if err != nil {
			break
		}
		class = c
	}
	if i >= len(spans) {
		return nil, fmt.Errorf("%w: missing type", ErrPresentationFormat)
	}
	rrtype, err := types.StringToRRType(text[spans[i][0]:spans[i][1]])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPresentationFormat, err)
	}
	if !hasTTL {
		return nil, fmt.Errorf("%w: no TTL and no $TTL", ErrPresentationFormat)
	}
	rdata := collapseBlanks(text[spans[i][1]:])
	if rdata == "" {
		return nil, fmt.Errorf("%w: missing RDATA", ErrPresentationFormat)
	}
	rr := &ResourceRecord{Label: owner, TTL: ttl, Class: class, Type: rrtype, Value: rdata}
	if err := checkEncodes(rr); err != nil {
		return nil, err
	}
	return rr, nil
}

// fieldSpans returns the [start, end) offsets of the blank-separated
// fields of s. Only the leading owner / TTL / class / type fields are
// read through it; the RDATA is taken as the rest of the text.
func fieldSpans(s string) [][2]int {
	var out [][2]int
	start := -1
	for i := 0; i <= len(s); i++ {
		blank := i == len(s) || s[i] == ' ' || s[i] == '\t'
		switch {
		case blank && start >= 0:
			out = append(out, [2]int{start, i})
			start = -1
		case !blank && start < 0:
			start = i
		}
	}
	return out
}

// collapseBlanks trims s and turns every run of blanks outside double
// quotes into one space.
func collapseBlanks(s string) string {
	var b strings.Builder
	inQuote, pendingSpace := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inQuote && (c == ' ' || c == '\t') {
			pendingSpace = b.Len() > 0
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		switch {
		case c == '\\' && i+1 < len(s):
			b.WriteByte(c)
			i++
			c = s[i]
		case c == '"':
			inQuote = !inQuote
		}
		b.WriteByte(c)
	}
	return b.String()
}

// checkEncodes encodes rr once; an error or an empty encoding (no
// encoder for the type) rejects the record.
func checkEncodes(rr *ResourceRecord) error {
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		if errors.Is(err, ErrRDataFormat) || errors.Is(err, ErrPresentationFormat) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrRDataFormat, err)
	}
	if len(b.Clone()) == 0 {
		return fmt.Errorf("%w: no encoder for type %s (register handlers or use the \\# form)",
			ErrRDataFormat, types.RRTypeName(rr.Type))
	}
	return nil
}
