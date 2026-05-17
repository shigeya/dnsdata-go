package dnssec_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shigeya/dnsdata-go/dnssec"
)

func TestBuiltinRootAnchors_ContainsKSK2017And2024(t *testing.T) {
	a := dnssec.BuiltinRootAnchors()
	if a == nil {
		t.Fatal("BuiltinRootAnchors() = nil")
	}
	if a.Source != "builtin" {
		t.Errorf("Source = %q, want \"builtin\"", a.Source)
	}
	if got := len(a.DS); got != 2 {
		t.Fatalf("DS count = %d, want 2", got)
	}

	tags := map[uint16]bool{}
	for _, ds := range a.DS {
		tags[ds.KeyTag] = true
		if ds.Algorithm != 8 {
			t.Errorf("KSK %d algorithm = %d, want 8 (RSASHA256)", ds.KeyTag, ds.Algorithm)
		}
		if ds.DigestType != 2 {
			t.Errorf("KSK %d digestType = %d, want 2 (SHA-256)", ds.KeyTag, ds.DigestType)
		}
		// SHA-256 hex string is exactly 64 chars.
		if len(ds.Digest) != 64 {
			t.Errorf("KSK %d digest length = %d, want 64", ds.KeyTag, len(ds.Digest))
		}
	}
	if !tags[20326] {
		t.Errorf("missing KSK-2017 (tag 20326)")
	}
	if !tags[38696] {
		t.Errorf("missing KSK-2024 (tag 38696)")
	}
}

// Each call to BuiltinRootAnchors must return an independent value;
// mutating the returned slice must not bleed into subsequent calls.
// (Asserts MUST NOT 22: no global mutable state.)
func TestBuiltinRootAnchors_IsCopy(t *testing.T) {
	a := dnssec.BuiltinRootAnchors()
	const sentinel uint16 = 65535
	a.DS[0].KeyTag = sentinel

	b := dnssec.BuiltinRootAnchors()
	if b.DS[0].KeyTag == sentinel {
		t.Errorf("BuiltinRootAnchors leaked mutation across calls")
	}
}

func TestReadAnchors_RoundTrip(t *testing.T) {
	src := dnssec.BuiltinRootAnchors()

	var buf bytes.Buffer
	if err := dnssec.WriteAnchors(&buf, src); err != nil {
		t.Fatalf("WriteAnchors: %v", err)
	}

	dst, err := dnssec.ReadAnchors(&buf)
	if err != nil {
		t.Fatalf("ReadAnchors: %v", err)
	}
	if dst.Source != src.Source || dst.LastUpdated != src.LastUpdated {
		t.Errorf("metadata mismatch: %+v vs %+v", dst, src)
	}
	if len(dst.DS) != len(src.DS) {
		t.Fatalf("DS count: got %d want %d", len(dst.DS), len(src.DS))
	}
	for i := range src.DS {
		if dst.DS[i] != src.DS[i] {
			t.Errorf("DS[%d] mismatch: got %+v want %+v", i, dst.DS[i], src.DS[i])
		}
	}
}

func TestReadAnchors_MalformedJSON(t *testing.T) {
	_, err := dnssec.ReadAnchors(strings.NewReader("not json"))
	if !errors.Is(err, dnssec.ErrAnchors) {
		t.Errorf("err = %v, want ErrAnchors", err)
	}
}

func TestReadAnchors_RejectsUnknownFields(t *testing.T) {
	// DisallowUnknownFields means a typo'd schema is caught early.
	const body = `{"source":"test","extra":"oops","lastUpdated":"x","ds":[],"dnskeys":[]}`
	_, err := dnssec.ReadAnchors(strings.NewReader(body))
	if !errors.Is(err, dnssec.ErrAnchors) {
		t.Errorf("err = %v, want ErrAnchors", err)
	}
}

func TestWriteAnchors_NilReturnsError(t *testing.T) {
	var buf bytes.Buffer
	err := dnssec.WriteAnchors(&buf, nil)
	if !errors.Is(err, dnssec.ErrAnchors) {
		t.Errorf("err = %v, want ErrAnchors", err)
	}
}

func TestDefaultAnchorsPath_EndsWithExpectedSegments(t *testing.T) {
	p, err := dnssec.DefaultAnchorsPath()
	if err != nil {
		t.Fatalf("DefaultAnchorsPath: %v", err)
	}
	// Path must end with ".dnsdata/root-anchors.json", platform-correct.
	want := filepath.Join(".dnsdata", "root-anchors.json")
	if !strings.HasSuffix(p, want) {
		t.Errorf("path %q does not end with %q", p, want)
	}
}

func TestRootAnchors_Clone_Nil(t *testing.T) {
	var a *dnssec.RootAnchors
	if a.Clone() != nil {
		t.Errorf("nil.Clone() returned non-nil")
	}
}
