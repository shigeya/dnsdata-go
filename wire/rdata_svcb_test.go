package wire_test

import (
	"encoding/hex"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// rdataPresentationCase is one RDataToString expectation. dnsdata-js
// tests the same bytes and strings (rdata_decoder.spec.ts).
type rdataPresentationCase struct {
	name  string
	qtype uint16
	rdata string // hex
	want  string
}

func runPresentationCases(t *testing.T, cases []rdataPresentationCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rdata, err := hex.DecodeString(tc.rdata)
			if err != nil {
				t.Fatalf("case hex: %v", err)
			}
			got, err := wire.RDataToString(rdata, tc.qtype, rdata, 0)
			if err != nil {
				t.Fatalf("RDataToString: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// RFC 6698 §2.2 / RFC 8162 §2: `usage selector matching-type hex`.
// Empty certificate data has no such form and stays generic.
func TestRDataToString_TLSA(t *testing.T) {
	runPresentationCases(t, []rdataPresentationCase{
		{"TLSA", types.TypeTLSA, "030101abcd", "3 1 1 abcd"},
		{"SMIMEA", types.TypeSMIMEA, "0300010A0B", "3 0 1 0a0b"},
		{"TLSA empty data", types.TypeTLSA, "030101", `\# 3 030101`},
	})
}

// RFC 9460 §2.1: `priority target key=value ...`, in the form
// zone.ParseSVCB reads. RDATA that form would not reproduce stays
// generic.
func TestRDataToString_SVCB(t *testing.T) {
	allKeys := "000100" +
		"0000000400010003" +
		"00010006026832026833" +
		"00020000" +
		"0003000220fb" +
		"00040008c0000201c0000202" +
		"00050003010203" +
		"0006001020010db8000000000000000000000001" +
		"fde80002abcd" +
		"fde90000"
	runPresentationCases(t, []rdataPresentationCase{
		{"SVCB", types.TypeSVCB, "000103737663076578616d706c6503636f6d00000100030268320003000201bb",
			"1 svc.example.com. alpn=h2 port=443"},
		{"HTTPS", types.TypeHTTPS, "00010000010003026832", "1 . alpn=h2"},
		{"AliasMode", types.TypeHTTPS, "000003666f6f00", "0 foo."},
		{"all keys", types.TypeSVCB, allKeys,
			"1 . mandatory=alpn,port alpn=h2,h3 no-default-alpn port=8443 " +
				"ipv4hint=192.0.2.1,192.0.2.2 ech=AQID ipv6hint=2001:db8::1 key65000=abcd key65001"},
		{"unsorted keys", types.TypeSVCB, "0001000003000201bb00010003026832",
			`\# 16 0001000003000201bb00010003026832`},
		{"alpn with comma", types.TypeSVCB, "0001000001000403612c62", `\# 11 0001000001000403612c62`},
		{"alpn empty", types.TypeSVCB, "00010000010000", `\# 7 00010000010000`},
		{"no-default-alpn with value", types.TypeSVCB, "0001000002000100", `\# 8 0001000002000100`},
		{"port short", types.TypeSVCB, "0001000003000101", `\# 8 0001000003000101`},
		{"ipv4hint ragged", types.TypeSVCB, "00010000040005c000020101", `\# 12 00010000040005c000020101`},
		{"ipv6hint IPv4-mapped", types.TypeSVCB, "0001000006001000000000000000000000ffffc0000201",
			`\# 23 0001000006001000000000000000000000ffffc0000201`},
		{"uppercase target", types.TypeSVCB, "000103464f4f00", `\# 7 000103464f4f00`},
		{"mandatory unsorted", types.TypeSVCB, "000100000000040003000100010003026832000300020035",
			`\# 24 000100000000040003000100010003026832000300020035`},
	})
}

// Malformed TLSA / SVCB RDATA stays generic, as before these types had
// a form of their own, so one bad record does not fail a response.
func TestRDataToString_TLSASVCBMalformed(t *testing.T) {
	runPresentationCases(t, []rdataPresentationCase{
		{"SVCB short", types.TypeSVCB, "0001", `\# 2 0001`},
		{"SVCB bad target", types.TypeSVCB, "000105", `\# 3 000105`},
		{"SVCB header truncated", types.TypeSVCB, "000100000100", `\# 6 000100000100`},
		{"SVCB value truncated", types.TypeSVCB, "0001000001000502", `\# 8 0001000001000502`},
		{"alpn id truncated", types.TypeSVCB, "000100000100020561", `\# 9 000100000100020561`},
		{"TLSA short", types.TypeTLSA, "0301", `\# 2 0301`},
	})
}
