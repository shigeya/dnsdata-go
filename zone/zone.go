package zone

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
)

// Zone is a collection of resource records keyed by (owner name, RR type).
// Records of the same key form an RRset (insertion order preserved).
//
// The zero value is ready to use.
type Zone struct {
	records map[rrsetKey][]*ResourceRecord
}

type rrsetKey struct {
	name string
	typ  uint16
}

// AddRRFromParts builds a [ResourceRecord] from textual fields and inserts
// it. class is either a numeric [types.Class*] (uint16 / int) or its
// mnemonic ("IN", "CHAOS", ...); rrtype likewise.
func (z *Zone) AddRRFromParts(label string, ttl uint32, class, rrtype any, value string) (*ResourceRecord, error) {
	rr, err := NewResourceRecord(label, ttl, class, rrtype, value)
	if err != nil {
		return nil, err
	}
	return z.AddRR(rr), nil
}

// AddRR appends rr to its RRset and returns it.
func (z *Zone) AddRR(rr *ResourceRecord) *ResourceRecord {
	if z.records == nil {
		z.records = map[rrsetKey][]*ResourceRecord{}
	}
	k := rrsetKey{name: rr.Label, typ: rr.Type}
	z.records[k] = append(z.records[k], rr)
	return rr
}

// FindRR returns the first record matching (name, rrtype), or nil if no
// RRset exists.
func (z *Zone) FindRR(name string, rrtype uint16) *ResourceRecord {
	if rrs := z.FindRRSet(name, rrtype); len(rrs) > 0 {
		return rrs[0]
	}
	return nil
}

// FindRRSet returns all records matching (name, rrtype). Returns nil if
// no RRset exists.
func (z *Zone) FindRRSet(name string, rrtype uint16) []*ResourceRecord {
	if z.records == nil {
		return nil
	}
	return z.records[rrsetKey{name: name, typ: rrtype}]
}

// AllRecords returns every record in the zone. Insertion order within each
// RRset is preserved; the order of RRsets relative to one another is
// implementation-defined (map iteration).
func (z *Zone) AllRecords() []*ResourceRecord {
	if z.records == nil {
		return nil
	}
	var out []*ResourceRecord
	for _, rrs := range z.records {
		out = append(out, rrs...)
	}
	return out
}

// Print returns the presentation form of every record, one per line. If
// onlyType is non-zero only records of that type are emitted.
func (z *Zone) Print(onlyType uint16) string {
	var lines []string
	for _, rrs := range z.records {
		for _, rr := range rrs {
			if onlyType == 0 || rr.Type == onlyType {
				lines = append(lines, rr.String())
			}
		}
	}
	return strings.Join(lines, "\n")
}

// ---- Master-file parser --------------------------------------------------

var (
	commentRE     = regexp.MustCompile(`\s*;.*$`)
	blankLineRE   = regexp.MustCompile(`^\s*$`)
	openParenRE   = regexp.MustCompile(`^(.*)\((.*)$`)
	closeParenRE  = regexp.MustCompile(`^(.*)\)(.*)$`)
	originRE      = regexp.MustCompile(`(?i)^\$ORIGIN\s+(\S+)`)
	ttlDirRE      = regexp.MustCompile(`(?i)^\$TTL\s+(\d+)`)
	leadingWSRE   = regexp.MustCompile(`^\s+`)
	withClassRE   = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(IN)\s+(\S+)\s+(.*)$`)
	noClassRE     = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\S+)\s+(.*)$`)
	defTTLClassRE = regexp.MustCompile(`^(\S+)\s+(IN)\s+(\S+)\s+(.*)$`)
	defTTLNoClsRE = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(.*)$`)
)

// ReadString parses RFC 1035 master-file text and inserts each RR found.
// Supports the `$ORIGIN`, `$TTL` directives, parenthesised continuations,
// `;` comments, leading-whitespace label inheritance, and implicit class
// (`IN`) — matching dnsdata-js's `read_string`.
//
// On a malformed line ReadString silently skips it (TS parity); future
// strict mode is tracked as a follow-up in DESIGN.md.
func (z *Zone) ReadString(text string) error {
	lines := strings.Split(text, "\n")
	var continuation string
	var prevLabel, origin string
	var defaultTTL uint32

	qualify := func(name string) string {
		if origin == "" {
			return name
		}
		if name == "@" {
			return origin
		}
		if strings.HasSuffix(name, ".") {
			return name
		}
		return name + "." + origin
	}

	for _, raw := range lines {
		line := commentRE.ReplaceAllString(raw, "")
		if blankLineRE.MatchString(line) {
			continue
		}

		if continuation != "" {
			if m := closeParenRE.FindStringSubmatch(line); m != nil {
				continuation += " " + strings.TrimSpace(m[1])
				if tail := strings.TrimSpace(m[2]); tail != "" {
					continuation += " " + tail
				}
				line = continuation
				continuation = ""
			} else {
				continuation += " " + strings.TrimSpace(line)
				continue
			}
		} else if m := openParenRE.FindStringSubmatch(line); m != nil {
			continuation = strings.TrimSpace(m[1])
			if tail := strings.TrimSpace(m[2]); tail != "" {
				continuation += " " + tail
			}
			continue
		}

		if m := originRE.FindStringSubmatch(line); m != nil {
			origin = m[1]
			continue
		}
		if m := ttlDirRE.FindStringSubmatch(line); m != nil {
			n, _ := strconv.ParseUint(m[1], 10, 32)
			defaultTTL = uint32(n)
			continue
		}

		if leadingWSRE.MatchString(line) {
			line = prevLabel + line
		}

		if m := withClassRE.FindStringSubmatch(line); m != nil {
			ttl, _ := strconv.ParseUint(m[2], 10, 32)
			if _, err := z.AddRRFromParts(qualify(m[1]), uint32(ttl), m[3], m[4], m[5]); err == nil {
				prevLabel = m[1]
			}
			continue
		}
		if m := noClassRE.FindStringSubmatch(line); m != nil {
			ttl, _ := strconv.ParseUint(m[2], 10, 32)
			if _, err := z.AddRRFromParts(qualify(m[1]), uint32(ttl), "IN", m[3], m[4]); err == nil {
				prevLabel = m[1]
			}
			continue
		}
		if defaultTTL > 0 {
			if m := defTTLClassRE.FindStringSubmatch(line); m != nil {
				if _, err := z.AddRRFromParts(qualify(m[1]), defaultTTL, m[2], m[3], m[4]); err == nil {
					prevLabel = m[1]
				}
				continue
			}
			if m := defTTLNoClsRE.FindStringSubmatch(line); m != nil {
				if _, err := types.StringToRRType(m[2]); err == nil {
					if _, err := z.AddRRFromParts(qualify(m[1]), defaultTTL, "IN", m[2], m[3]); err == nil {
						prevLabel = m[1]
					}
				}
				continue
			}
		}
	}
	return nil
}
