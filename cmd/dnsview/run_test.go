package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// signedDir is the signed hierarchy shared with dnsdata-js.
var signedDir = filepath.Join("..", "..", "testdata", "signed")

var anchorsFile = filepath.Join(signedDir, "root-anchors.json")

var vectorClock = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

type vectorCase struct {
	QName   string `json:"qname"`
	QType   uint16 `json:"qtype"`
	Clock   string `json:"clock"`
	Verdict string `json:"verdict"`
}

// outLine mirrors line with the Result kept raw, so tests see the JSON
// exactly as written.
type outLine struct {
	Query  query           `json:"query"`
	Server string          `json:"server"`
	Error  string          `json:"error"`
	Result json.RawMessage `json:"result"`
}

func loadAuthority(t *testing.T) *memory.Authority {
	t.Helper()
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
	var opts []memory.Option
	for _, vz := range []struct{ apex, file string }{
		{".", "root.zone"}, {"test.", "test.zone"}, {"example.test.", "example.test.zone"},
	} {
		text, err := os.ReadFile(filepath.Join(signedDir, vz.file))
		if err != nil {
			t.Fatal(err)
		}
		var z zone.Zone
		if err := z.ReadStringStrict(string(text)); err != nil {
			t.Fatal(err)
		}
		opts = append(opts, memory.WithZone(vz.apex, &z))
	}
	a, err := memory.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func loadCases(t *testing.T) []vectorCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(signedDir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []vectorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// runWith runs dnsview with r as the transport and the clock at now.
func runWith(t *testing.T, r verifier.Resolver, now time.Time, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, env{
		stdout:      &stdout,
		stderr:      &stderr,
		now:         func() time.Time { return now },
		newResolver: func(config) verifier.Resolver { return r },
	})
	return code, stdout.String(), stderr.String()
}

func decodeLines(t *testing.T, out string) []outLine {
	t.Helper()
	var lines []outLine
	for _, s := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var l outLine
		if err := json.Unmarshal([]byte(s), &l); err != nil {
			t.Fatalf("line %q: %v", s, err)
		}
		lines = append(lines, l)
	}
	return lines
}

func decodeResult(t *testing.T, raw json.RawMessage) verifier.Result {
	t.Helper()
	var r verifier.Result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("result %s: %v", raw, err)
	}
	return r
}

// checkVerdictFields asserts the fields each verdict is defined to carry.
func checkVerdictFields(t *testing.T, r verifier.Result) {
	t.Helper()
	switch r.Verdict {
	case verifier.VerdictSecure:
		if r.Answer == nil || len(r.Answer.Records) == 0 {
			t.Errorf("secure without answer: %+v", r)
		}
	case verifier.VerdictSecureNoData, verifier.VerdictSecureNXDomain:
		if r.NegativeReason == "" || r.Answer != nil {
			t.Errorf("%s: negativeReason %q, answer %v", r.Verdict, r.NegativeReason, r.Answer)
		}
	case verifier.VerdictInsecure:
		if r.InsecureAt == "" || r.Answer != nil {
			t.Errorf("insecure: insecureAt %q, answer %v", r.InsecureAt, r.Answer)
		}
	case verifier.VerdictBogus:
		if r.BogusAt == "" || r.BogusReason == "" || r.Answer != nil {
			t.Errorf("bogus: bogusAt %q, bogusReason %q, answer %v", r.BogusAt, r.BogusReason, r.Answer)
		}
	}
	// A bogus root DNSKEY rrset (signature out of its window) fails
	// before the first step is recorded.
	if len(r.Chain) == 0 && r.Verdict != verifier.VerdictBogus {
		t.Errorf("%s: empty chain", r.Verdict)
	}
}

func TestRun_SignedVectors(t *testing.T) {
	a := loadAuthority(t)
	for _, c := range loadCases(t) {
		t.Run(c.QName+"/"+c.Clock, func(t *testing.T) {
			clock, err := time.Parse(time.RFC3339, c.Clock)
			if err != nil {
				t.Fatal(err)
			}
			// Lower case on purpose: types are matched in any case.
			typ := strings.ToLower(typeName(c.QType))
			code, out, stderr := runWith(t, a, clock, "-server", "192.0.2.53", "-anchors", anchorsFile, "-type", typ, c.QName)
			if code != exitOK {
				t.Fatalf("exit %d, stderr %s", code, stderr)
			}
			lines := decodeLines(t, out)
			if len(lines) != 1 {
				t.Fatalf("%d lines, want 1", len(lines))
			}
			l := lines[0]
			wantQuery := query{Name: c.QName, Type: typeName(c.QType)}
			if l.Query != wantQuery || l.Server != "192.0.2.53:53" || l.Error != "" {
				t.Errorf("line %+v, want query %+v server 192.0.2.53:53 no error", l, wantQuery)
			}
			r := decodeResult(t, l.Result)
			if r.Verdict.String() != c.Verdict {
				t.Errorf("verdict %s, want %s (%s)", r.Verdict, c.Verdict, r.BogusReason)
			}
			checkVerdictFields(t, r)
		})
	}
}

// The result is the verifier's Result marshalled as is, under "result".
func TestRun_ResultIsVerifierResultAsIs(t *testing.T) {
	a := loadAuthority(t)
	_, out, _ := runWith(t, a, vectorClock, "-server", "192.0.2.53", "-anchors", anchorsFile, "www.example.test.")

	anchors, err := loadAnchors(anchorsFile)
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.NewVerifier(verifier.WithResolver(a), verifier.WithTrustAnchors(anchors),
		verifier.WithClock(func() time.Time { return vectorClock }))
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Validate(context.Background(), "www.example.test.", 1)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 || top["query"] == nil || top["server"] == nil {
		t.Errorf("top-level keys %v, want query, server, result", keys(top))
	}
	if !bytes.Equal(top["result"], want) {
		t.Errorf("result\n%s\nwant\n%s", top["result"], want)
	}
}

// NAME goes to Validate as typed. The verifier lower-cases it and adds
// the trailing dot, so any spelling gives the verdict and the result of
// the canonical name; query.name echoes the spelling given.
func TestRun_NameSpellings(t *testing.T) {
	a := loadAuthority(t)
	resultOf := func(t *testing.T, name, typ string) (outLine, map[string]json.RawMessage) {
		t.Helper()
		code, out, stderr := runWith(t, a, vectorClock, "-server", "192.0.2.53", "-anchors", anchorsFile, "-type", typ, name)
		if code != exitOK {
			t.Fatalf("%s: exit %d, stderr %s", name, code, stderr)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &top); err != nil {
			t.Fatal(err)
		}
		return decodeLines(t, out)[0], top
	}
	for _, c := range []struct {
		canonical, typ, verdict string
		spellings               []string
	}{
		{"test.", "SOA", "secure", []string{"test", "Test.", "TEST"}},
		{"www.example.test.", "A", "secure", []string{"www.example.test", "WWW.Example.TEST.", "Www.Example.Test"}},
		{"example.test.", "SOA", "secure", []string{"example.test", "Example.Test.", "EXAMPLE.TEST"}},
		{"nope.example.test.", "A", "secure-nxdomain", []string{"nope.example.test", "NOPE.example.test."}},
		{"www.example.test.", "MX", "secure-nodata", []string{"WWW.EXAMPLE.TEST"}},
		{"x.wild.example.test.", "A", "secure", []string{"X.Wild.Example.Test"}},
		{"alias.example.test.", "A", "secure", []string{"Alias.Example.Test"}},
		{"www.insecure.test.", "A", "insecure", []string{"WWW.Insecure.Test"}},
	} {
		_, want := resultOf(t, c.canonical, c.typ)
		for _, s := range c.spellings {
			t.Run(s+"/"+c.typ, func(t *testing.T) {
				l, got := resultOf(t, s, c.typ)
				if v := decodeResult(t, l.Result).Verdict.String(); v != c.verdict {
					t.Errorf("verdict %s, want %s", v, c.verdict)
				}
				if l.Query.Name != s {
					t.Errorf("query.name %q, want %q as given", l.Query.Name, s)
				}
				if !bytes.Equal(got["result"], want["result"]) {
					t.Errorf("result differs from %s:\n%s\nwant\n%s", c.canonical, got["result"], want["result"])
				}
			})
		}
	}
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRun_OneLinePerNameAndType(t *testing.T) {
	a := loadAuthority(t)
	code, out, stderr := runWith(t, a, vectorClock, "-server", "192.0.2.53:5353", "-anchors", anchorsFile,
		"-type", "A, mx", "www.example.test.", "nope.example.test.")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	want := []struct{ name, typ, verdict string }{
		{"www.example.test.", "A", "secure"},
		{"www.example.test.", "MX", "secure-nodata"},
		{"nope.example.test.", "A", "secure-nxdomain"},
		{"nope.example.test.", "MX", "secure-nxdomain"},
	}
	lines := decodeLines(t, out)
	if len(lines) != len(want) {
		t.Fatalf("%d lines, want %d", len(lines), len(want))
	}
	for i, w := range want {
		l := lines[i]
		got := decodeResult(t, l.Result).Verdict.String()
		if l.Query.Name != w.name || l.Query.Type != w.typ || l.Server != "192.0.2.53:5353" || got != w.verdict {
			t.Errorf("line %d: %+v verdict %s, want %+v", i, l, got, w)
		}
	}
}

// Without -anchors the built-in IANA anchors are used, which do not
// match the private root.
func TestRun_BuiltinAnchorsByDefault(t *testing.T) {
	a := loadAuthority(t)
	_, out, _ := runWith(t, a, vectorClock, "-server", "192.0.2.53", "www.example.test.")
	r := decodeResult(t, decodeLines(t, out)[0].Result)
	if r.Verdict == verifier.VerdictSecure {
		t.Errorf("verdict secure under the IANA anchors: %+v", r)
	}
}

func TestRun_ResolverErrorIsReportedPerLine(t *testing.T) {
	failing := verifier.ResolverFunc(func(context.Context, string, uint16) (resolver.Response, error) {
		return resolver.Response{}, errors.New("unreachable")
	})
	code, out, _ := runWith(t, failing, vectorClock, "-server", "192.0.2.53", "a.test.", "b.test.")
	if code != exitQueryError {
		t.Errorf("exit %d, want %d", code, exitQueryError)
	}
	lines := decodeLines(t, out)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}
	for _, l := range lines {
		if !strings.Contains(l.Error, "unreachable") {
			t.Errorf("error %q, want the resolver's", l.Error)
		}
		if string(l.Result) != "null" {
			if v := decodeResult(t, l.Result).Verdict; v != verifier.VerdictIndeterminate {
				t.Errorf("verdict %s, want indeterminate", v)
			}
		}
	}
}

func TestRun_ConfigReachesTheResolver(t *testing.T) {
	var got config
	var stdout, stderr bytes.Buffer
	run([]string{"-server", "2001:db8::53", "-cd", "-timeout", "3s", "x.test."}, env{
		stdout: &stdout, stderr: &stderr, now: time.Now,
		newResolver: func(cfg config) verifier.Resolver {
			got = cfg
			return verifier.ResolverFunc(func(context.Context, string, uint16) (resolver.Response, error) {
				return resolver.Response{}, errors.New("offline")
			})
		},
	})
	if got.server != "[2001:db8::53]:53" || !got.cd || got.timeout != 3*time.Second {
		t.Errorf("config %+v", got)
	}
	if len(got.queries) != 1 || got.queries[0].Type != "A" {
		t.Errorf("queries %+v, want one A", got.queries)
	}
}

func TestRun_UsageErrors(t *testing.T) {
	cases := map[string][]string{
		"no server":       {"x.test."},
		"no name":         {"-server", "192.0.2.53"},
		"unknown type":    {"-server", "192.0.2.53", "-type", "NOSUCHTYPE", "x.test."},
		"zero timeout":    {"-server", "192.0.2.53", "-timeout", "0s", "x.test."},
		"missing anchors": {"-server", "192.0.2.53", "-anchors", filepath.Join(t.TempDir(), "none.json"), "x.test."},
		"bad anchors":     {"-server", "192.0.2.53", "-anchors", filepath.Join(signedDir, "root.zone"), "x.test."},
		"unknown flag":    {"-bogus"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, stderr := runWith(t, nil, vectorClock, args...)
			if code != exitUsage || out != "" || !strings.Contains(stderr, "usage: dnsview") {
				t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
			}
		})
	}
}

func TestRun_Help(t *testing.T) {
	code, out, stderr := runWith(t, nil, vectorClock, "-h")
	if code != exitOK || out != "" || !strings.Contains(stderr, "-server") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}

func TestTypeName(t *testing.T) {
	for in, want := range map[uint16]string{1: "A", 15: "MX", 65400: "TYPE65400"} {
		if got := typeName(in); got != want {
			t.Errorf("typeName(%d) = %q, want %q", in, got, want)
		}
	}
	if got := fmt.Sprint(crossQueries([]string{"a."}, []uint16{1, 28})); !strings.Contains(got, "AAAA") {
		t.Errorf("crossQueries = %s", got)
	}
}
