package zone_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/naptr_rr.spec.ts.

func TestParseNAPTR_ENUMExample(t *testing.T) {
	// RFC 6116 ENUM example. The zone-file octets `\\` decode to a
	// single backslash before reaching ParseNAPTR; here we pass the
	// post-zone-parser value with single backslashes.
	v := `100 10 "u" "E2U+sip" "!^\+(.*)$!sip:\1@example.com!" .`
	rr := newRR(t, "2.1.2.1.5.5.5.0.0.8.1.e164.arpa.", 3600, "IN", "NAPTR", v)
	h, err := zone.ParseNAPTR(rr, v)
	if err != nil {
		t.Fatalf("ParseNAPTR: %v", err)
	}
	if h.Order != 100 || h.Preference != 10 {
		t.Errorf("order/preference = %d/%d, want 100/10", h.Order, h.Preference)
	}
	if h.Flags != "u" || h.Services != "E2U+sip" {
		t.Errorf("flags/services = %q/%q", h.Flags, h.Services)
	}
	if want := `!^+(.*)$!sip:1@example.com!`; h.Regexp != want {
		// Backslash-escape semantics: `\+` → `+`, `\1` → `1` (TS parity).
		t.Errorf("Regexp = %q, want %q", h.Regexp, want)
	}
	if h.Replacement != "." {
		t.Errorf("Replacement = %q, want .", h.Replacement)
	}
}

func TestParseNAPTR_SIPExample(t *testing.T) {
	v := `10 100 "s" "SIP+D2U" "" _sip._udp.example.com.`
	h, err := zone.ParseNAPTR(nil, v)
	if err != nil {
		t.Fatalf("ParseNAPTR: %v", err)
	}
	if h.Order != 10 || h.Preference != 100 || h.Flags != "s" || h.Services != "SIP+D2U" {
		t.Errorf("parsed = {%d %d %q %q}", h.Order, h.Preference, h.Flags, h.Services)
	}
	if h.Regexp != "" {
		t.Errorf("Regexp = %q, want empty", h.Regexp)
	}
	if h.Replacement != "_sip._udp.example.com." {
		t.Errorf("Replacement = %q", h.Replacement)
	}
}

func TestParseNAPTR_EmptyFlags(t *testing.T) {
	v := `100 50 "" "http+N2L+N2C+N2R" "" www.example.com.`
	h, err := zone.ParseNAPTR(nil, v)
	if err != nil {
		t.Fatalf("ParseNAPTR: %v", err)
	}
	if h.Flags != "" {
		t.Errorf("Flags = %q, want empty", h.Flags)
	}
	if h.Services != "http+N2L+N2C+N2R" {
		t.Errorf("Services = %q", h.Services)
	}
	if h.Replacement != "www.example.com." {
		t.Errorf("Replacement = %q", h.Replacement)
	}
}

func TestParseNAPTR_Malformed(t *testing.T) {
	for _, v := range []string{
		"",
		"10",                            // missing every other field
		`10 100 s SIP+D2U "" .`,         // unquoted flags
		`10 100 "s" "SIP+D2U" "" `,      // missing replacement
		`10 100 "s" "SIP+D2U" "unterm `, // unterminated quote
	} {
		if _, err := zone.ParseNAPTR(nil, v); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseNAPTR(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestNAPTR_WireBody(t *testing.T) {
	v := `10 100 "s" "SIP+D2U" "" _sip._udp.example.com.`
	h, err := zone.ParseNAPTR(nil, v)
	if err != nil {
		t.Fatalf("ParseNAPTR: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := binary.BigEndian.Uint16(out[0:2])
	if int(rdlen)+2 != len(out) {
		t.Errorf("rdlen %d + 2 != len(out) %d", rdlen, len(out))
	}
	if got := binary.BigEndian.Uint16(out[2:4]); got != 10 {
		t.Errorf("order = %d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(out[4:6]); got != 100 {
		t.Errorf("preference = %d, want 100", got)
	}
	// flags character-string: len=1, 's'
	if out[6] != 1 || out[7] != 's' {
		t.Errorf("flags cs = %v %q, want 1 \"s\"", out[6], out[7])
	}
	// services character-string: len=7, "SIP+D2U"
	if out[8] != 7 || string(out[9:16]) != "SIP+D2U" {
		t.Errorf("services cs = %v %q", out[8], out[9:16])
	}
	// regexp character-string: len=0
	if out[16] != 0 {
		t.Errorf("regexp len = %d, want 0", out[16])
	}
}

func TestNAPTR_Rdlength(t *testing.T) {
	v := `10 100 "s" "SIP+D2U" "" _sip._udp.example.com.`
	h, err := zone.ParseNAPTR(nil, v)
	if err != nil {
		t.Fatalf("ParseNAPTR: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	rdlen := binary.BigEndian.Uint16(out[0:2])
	// replacement: _sip(4+1) + _udp(4+1) + example(7+1) + com(3+1) + root(1) = 23
	replacementLen := 1 + 4 + 1 + 4 + 1 + 7 + 1 + 3 + 1
	expected := 2 + 2 + (1 + 1) + (1 + 7) + (1 + 0) + replacementLen
	if int(rdlen) != expected {
		t.Errorf("rdlen = %d, want %d", rdlen, expected)
	}
	if len(out) != 2+expected {
		t.Errorf("total = %d, want %d", len(out), 2+expected)
	}
}

func TestNAPTR_Clone(t *testing.T) {
	v := `10 100 "s" "SIP+D2U" "" _sip._udp.example.com.`
	h, err := zone.ParseNAPTR(nil, v)
	if err != nil {
		t.Fatalf("ParseNAPTR: %v", err)
	}
	cloned, ok := h.Clone().(*zone.NAPTR)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.Order != h.Order || cloned.Replacement != h.Replacement {
		t.Errorf("Clone fields differ")
	}
}

func TestZone_ReadString_NAPTRRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
@  IN  NAPTR  10 100 "s" "SIP+D2U" "" _sip._udp.example.com.
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("example.com.", types.TypeNAPTR)
	if rr == nil {
		t.Fatalf("NAPTR record missing")
	}
	h, ok := rr.Handler().(*zone.NAPTR)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.NAPTR", rr.Handler())
	}
	if h.Order != 10 || h.Preference != 100 || h.Flags != "s" || h.Services != "SIP+D2U" {
		t.Errorf("parsed = {%d %d %q %q}", h.Order, h.Preference, h.Flags, h.Services)
	}
}
