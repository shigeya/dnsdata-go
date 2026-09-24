package memory_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// update regenerates testdata/signed. Signatures are ECDSA and differ on
// every run, so regenerate only when the hierarchy itself changes.
var update = flag.Bool("update", false, "regenerate testdata/signed")

// signedDir holds a signed hierarchy (fake root, test., example.test.)
// shared with dnsdata-js: the zones as canonical master files, the BIND
// private keys that signed them, the root trust anchors, and the
// expected verdicts.
var signedDir = filepath.Join("..", "..", "testdata", "signed")

var vectorZones = []struct{ apex, file string }{
	{".", "root.zone"},
	{"test.", "test.zone"},
	{"example.test.", "example.test.zone"},
}

type vectorCase struct {
	QName   string `json:"qname"`
	QType   uint16 `json:"qtype"`
	Clock   string `json:"clock"`
	Verdict string `json:"verdict"`
}

var vectorCases = []vectorCase{
	{"www.example.test.", 1, "2026-06-01T00:00:00Z", "secure"},
	{"key.example.test.", 65400, "2026-06-01T00:00:00Z", "secure"},
	{"nope.example.test.", 1, "2026-06-01T00:00:00Z", "secure-nxdomain"},
	{"www.example.test.", 15, "2026-06-01T00:00:00Z", "secure-nodata"},
	{"x.wild.example.test.", 1, "2026-06-01T00:00:00Z", "secure"},
	{"alias.example.test.", 1, "2026-06-01T00:00:00Z", "secure"},
	{"www.insecure.test.", 1, "2026-06-01T00:00:00Z", "insecure"},
	{"www.example.test.", 1, "2036-06-01T00:00:00Z", "bogus"},
	{"www.example.test.", 1, "2025-06-01T00:00:00Z", "bogus"},
}

const vectorDescription = "Signed hierarchy shared by dnsdata-go and dnsdata-js: a private root (trust anchor in " +
	"root-anchors.json), test., and example.test., signed with the BIND keys in keys/ for " +
	"2026-01-01..2036-01-01. Serve the three zone files from an in-memory authority, validate each " +
	"case at its clock, and expect the verdict. Keep these files byte-identical in both repositories."

func TestSignedVectors(t *testing.T) {
	if *update {
		writeVectors(t)
	}
	auth := loadVectorAuthority(t)
	anchors := loadVectorAnchors(t)
	for _, c := range loadVectorCases(t) {
		t.Run(c.QName+"/"+c.Clock, func(t *testing.T) {
			clock, err := time.Parse(time.RFC3339, c.Clock)
			if err != nil {
				t.Fatal(err)
			}
			v, err := verifier.NewVerifier(
				verifier.WithResolver(auth),
				verifier.WithTrustAnchors(anchors),
				verifier.WithClock(func() time.Time { return clock }),
			)
			if err != nil {
				t.Fatal(err)
			}
			res, err := v.Validate(context.Background(), c.QName, c.QType)
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict.String() != c.Verdict {
				t.Errorf("verdict %s, want %s (%s)", res.Verdict, c.Verdict, res.BogusReason)
			}
		})
	}
}

func loadVectorAuthority(t *testing.T) *memory.Authority {
	t.Helper()
	var opts []memory.Option
	for _, vz := range vectorZones {
		text, err := os.ReadFile(filepath.Join(signedDir, vz.file))
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, memory.WithZone(vz.apex, readZone(t, string(text))))
	}
	a, err := memory.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func loadVectorAnchors(t *testing.T) *dnssec.RootAnchors {
	t.Helper()
	f, err := os.Open(filepath.Join(signedDir, "root-anchors.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a, err := dnssec.ReadAnchors(f)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func loadVectorCases(t *testing.T) []vectorCase {
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

// writeVectors regenerates testdata/signed (only with -update).
func writeVectors(t *testing.T) {
	t.Helper()
	h := buildHierarchy(t)
	if err := os.MkdirAll(filepath.Join(signedDir, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, z := range []*zone.Zone{h.root, h.tld, h.leaf} {
		text, err := z.PrintCanonical(0)
		if err != nil {
			t.Fatal(err)
		}
		writeVectorFile(t, vectorZones[i].file, []byte(text+"\n"))
	}
	for _, k := range hierarchyKeys {
		writeVectorFile(t, filepath.Join("keys", k.seed+".private"), []byte(bindPrivateText(k.seed)))
	}
	anchors, err := signer.RootAnchors(h.rootKSK)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := dnssec.WriteAnchors(&buf, anchors); err != nil {
		t.Fatal(err)
	}
	writeVectorFile(t, "root-anchors.json", buf.Bytes())
	cases, err := json.MarshalIndent(struct {
		Description string       `json:"description"`
		Cases       []vectorCase `json:"cases"`
	}{vectorDescription, vectorCases}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeVectorFile(t, "cases.json", append(cases, '\n'))
}

func writeVectorFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(signedDir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
