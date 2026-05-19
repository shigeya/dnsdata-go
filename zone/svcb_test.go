package zone_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// Ported from dnsdata-js/packages/core/tests/zone/rr/svcb_rr.spec.ts.

func TestParseSVCB_AliasMode(t *testing.T) {
	// Priority 0 + target only (RFC 9460 §2.4.2).
	rr := newRR(t, "_https._tcp.example.com.", 3600, "IN", "SVCB", "0 svc.example.com.")
	h, err := zone.ParseSVCB(rr, "0 svc.example.com.")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	if h.Priority != 0 || h.Target != "svc.example.com." {
		t.Errorf("parsed = {%d %q}", h.Priority, h.Target)
	}
	if len(h.Params) != 0 {
		t.Errorf("Params len = %d, want 0", len(h.Params))
	}
}

func TestParseSVCB_ServiceModeAlpn(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "1 . alpn=h2,h3")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	if h.Priority != 1 || h.Target != "." {
		t.Errorf("priority/target = %d/%q", h.Priority, h.Target)
	}
	if len(h.Params) != 1 || h.Params[0].Key != zone.SvcKeyAlpn {
		t.Errorf("Params[0] = %+v, want alpn", h.Params)
	}
}

func TestParseSVCB_Port(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "1 svc.example.com. port=8443")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	if len(h.Params) != 1 || h.Params[0].Key != zone.SvcKeyPort {
		t.Fatalf("Params[0] = %+v", h.Params)
	}
	// 8443 = 0x20FB
	if !bytes.Equal(h.Params[0].Value, []byte{0x20, 0xFB}) {
		t.Errorf("port wire = %x, want 20FB", h.Params[0].Value)
	}
}

func TestParseSVCB_MultipleParamsSorted(t *testing.T) {
	// Presentation has port=443 before alpn=h2 — wire must be sorted by key.
	h, err := zone.ParseSVCB(nil, "1 svc.example.com. port=443 alpn=h2")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	if len(h.Params) != 2 {
		t.Fatalf("Params len = %d", len(h.Params))
	}
	if h.Params[0].Key != zone.SvcKeyAlpn || h.Params[1].Key != zone.SvcKeyPort {
		t.Errorf("keys = %d/%d, want %d/%d", h.Params[0].Key, h.Params[1].Key, zone.SvcKeyAlpn, zone.SvcKeyPort)
	}
}

func TestSVCB_WireBody_AliasMode(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "0 svc.example.com.")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	// svc.example.com. → 3+svc + 7+example + 3+com + 0 = 17
	expectedTargetLen := 17
	if got := binary.BigEndian.Uint16(out[0:2]); int(got) != 2+expectedTargetLen {
		t.Errorf("rdlen = %d, want %d", got, 2+expectedTargetLen)
	}
	if got := binary.BigEndian.Uint16(out[2:4]); got != 0 {
		t.Errorf("priority = %d, want 0", got)
	}
	if out[4] != 3 || string(out[5:8]) != "svc" {
		t.Errorf("first label = %d %q", out[4], out[5:8])
	}
}

func TestSVCB_WireBody_RootTarget(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "1 . alpn=h2")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	var b wire.Builder
	if err := h.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	out := b.Bytes()
	if got := binary.BigEndian.Uint16(out[2:4]); got != 1 {
		t.Errorf("priority = %d, want 1", got)
	}
	if out[4] != 0 {
		t.Errorf("root label byte = %d, want 0", out[4])
	}
	// SvcParamKey follows immediately after the root.
	if got := binary.BigEndian.Uint16(out[5:7]); got != zone.SvcKeyAlpn {
		t.Errorf("first SvcParamKey = %d, want alpn (%d)", got, zone.SvcKeyAlpn)
	}
}

func TestSVCB_AlpnWireFormat(t *testing.T) {
	// h2/h3 = 2/'h'/'2' + 2/'h'/'3' = 6 bytes
	h, err := zone.ParseSVCB(nil, "1 . alpn=h2,h3")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	p := h.Params[0]
	if p.Key != zone.SvcKeyAlpn {
		t.Fatalf("Key = %d, want alpn", p.Key)
	}
	want := []byte{2, 'h', '2', 2, 'h', '3'}
	if !bytes.Equal(p.Value, want) {
		t.Errorf("Value = %x, want %x", p.Value, want)
	}
}

func TestSVCB_IPv4Hint(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "1 . ipv4hint=192.0.2.1,192.0.2.2")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	p := h.Params[0]
	if p.Key != zone.SvcKeyIPv4Hint {
		t.Fatalf("Key = %d, want ipv4hint", p.Key)
	}
	want := []byte{192, 0, 2, 1, 192, 0, 2, 2}
	if !bytes.Equal(p.Value, want) {
		t.Errorf("Value = %x, want %x", p.Value, want)
	}
}

func TestSVCB_IPv6Hint(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "1 . ipv6hint=2001:db8::1")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	p := h.Params[0]
	if p.Key != zone.SvcKeyIPv6Hint {
		t.Fatalf("Key = %d, want ipv6hint", p.Key)
	}
	if len(p.Value) != 16 {
		t.Fatalf("Value length = %d, want 16", len(p.Value))
	}
	if p.Value[0] != 0x20 || p.Value[1] != 0x01 || p.Value[2] != 0x0d || p.Value[3] != 0xb8 {
		t.Errorf("2001:0db8 prefix = %x", p.Value[:4])
	}
	for i := 4; i < 15; i++ {
		if p.Value[i] != 0 {
			t.Errorf("byte %d = %02x, want 0", i, p.Value[i])
		}
	}
	if p.Value[15] != 1 {
		t.Errorf("trailing byte = %02x, want 01", p.Value[15])
	}
}

func TestSVCB_Clone(t *testing.T) {
	h, err := zone.ParseSVCB(nil, "1 svc.example.com. alpn=h2 port=443")
	if err != nil {
		t.Fatalf("ParseSVCB: %v", err)
	}
	cloned, ok := h.Clone().(*zone.SVCB)
	if !ok {
		t.Fatalf("Clone returned %T", h.Clone())
	}
	if cloned.Priority != h.Priority || cloned.Target != h.Target {
		t.Errorf("Clone header differs")
	}
	if len(cloned.Params) != len(h.Params) {
		t.Errorf("Clone params len differs")
	}
	cloned.Params[0].Value[0] ^= 0xff
	if cloned.Params[0].Value[0] == h.Params[0].Value[0] {
		t.Errorf("Clone is not a deep copy")
	}
}

func TestParseSVCB_Malformed(t *testing.T) {
	for _, v := range []string{"", "invalid", "0", "abc target."} {
		if _, err := zone.ParseSVCB(nil, v); !errors.Is(err, zone.ErrPresentationFormat) {
			t.Errorf("ParseSVCB(%q) err = %v, want ErrPresentationFormat", v, err)
		}
	}
}

func TestHTTPS_SharesSVCBStruct(t *testing.T) {
	rr := newRR(t, "example.com.", 3600, "IN", "HTTPS", "1 . alpn=h2,h3")
	h, ok := rr.Handler().(*zone.SVCB)
	if !ok {
		t.Fatalf("Handler() returned %T, want *zone.SVCB (HTTPS reuses)", rr.Handler())
	}
	if h.Priority != 1 || h.Target != "." || len(h.Params) != 1 {
		t.Errorf("HTTPS parsed = {%d %q params=%d}", h.Priority, h.Target, len(h.Params))
	}
}

func TestHTTPS_MatchesSVCBWire(t *testing.T) {
	const v = "1 . alpn=h2"
	svcbRR := newRR(t, "example.com.", 3600, "IN", "SVCB", v)
	httpsRR := newRR(t, "example.com.", 3600, "IN", "HTTPS", v)
	var sb, hb wire.Builder
	if err := svcbRR.WireBody(&sb); err != nil {
		t.Fatalf("SVCB WireBody: %v", err)
	}
	if err := httpsRR.WireBody(&hb); err != nil {
		t.Fatalf("HTTPS WireBody: %v", err)
	}
	if !bytes.Equal(sb.Bytes(), hb.Bytes()) {
		t.Errorf("SVCB / HTTPS wire bodies differ:\nSVCB  = %x\nHTTPS = %x", sb.Bytes(), hb.Bytes())
	}
}

func TestZone_ReadString_SVCBRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
_https._tcp  IN  SVCB  1 svc.example.com. alpn=h2
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("_https._tcp.example.com.", types.TypeSVCB)
	if rr == nil {
		t.Fatalf("SVCB record missing")
	}
	h, ok := rr.Handler().(*zone.SVCB)
	if !ok {
		t.Fatalf("Handler() returned %T", rr.Handler())
	}
	if h.Priority != 1 || h.Target != "svc.example.com." {
		t.Errorf("parsed = {%d %q}", h.Priority, h.Target)
	}
}

func TestZone_ReadString_HTTPSRecord(t *testing.T) {
	var z zone.Zone
	text := `
$ORIGIN example.com.
$TTL 3600
@  IN  HTTPS  1 . alpn=h2,h3 port=443
`
	if err := z.ReadString(text); err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	rr := z.FindRR("example.com.", types.TypeHTTPS)
	if rr == nil {
		t.Fatalf("HTTPS record missing")
	}
	h, ok := rr.Handler().(*zone.SVCB)
	if !ok {
		t.Fatalf("Handler() returned %T", rr.Handler())
	}
	if h.Priority != 1 || len(h.Params) != 2 {
		t.Errorf("parsed = {%d params=%d}", h.Priority, len(h.Params))
	}
}
