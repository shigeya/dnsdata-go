package dnssec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrAnchors classifies failures from this file (parse, encode, ...).
// Concrete errors wrap it so callers can match with [errors.Is].
var ErrAnchors = errors.New("root anchors error")

// AnchorDS is a delegation-signer entry in a trust-anchor document.
//
// It is the JSON-friendly counterpart to [DS] (the RR handler in
// ds.go): KeyTag / Algorithm / DigestType match, but Digest is a
// hex string here so the trust-anchor file remains human-readable.
//
// JSON field tags match the dnsdata-js on-disk format
// (`~/.dnsdata/root-anchors.json`) so the same file can be shared
// between Go and TypeScript sibling implementations.
type AnchorDS struct {
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`
	Digest     string `json:"digest"` // upper-case hex
}

// AnchorDNSKEY is a DNSKEY entry in a trust-anchor document. Currently
// unused by the embedded built-in anchors (DNSKEY records for the root
// are fetched live during chain validation), but exposed so caller-
// supplied JSON can include them. It is the JSON-friendly counterpart
// to [DNSKey] (the RR handler in dnskey.go).
type AnchorDNSKEY struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"publicKey"` // base64
}

// RootAnchors carries a snapshot of root-zone trust anchors. The shape
// is wire-compatible with `RootAnchors` in dnsdata-js so the two
// implementations can read each other's `root-anchors.json`.
type RootAnchors struct {
	LastUpdated string         `json:"lastUpdated"`
	Source      string         `json:"source"`
	DS          []AnchorDS     `json:"ds"`
	DNSKEYs     []AnchorDNSKEY `json:"dnskeys"`
}

// Clone returns a deep copy of a — callers may mutate the result
// without affecting the receiver.
func (a *RootAnchors) Clone() *RootAnchors {
	if a == nil {
		return nil
	}
	out := &RootAnchors{
		LastUpdated: a.LastUpdated,
		Source:      a.Source,
	}
	if a.DS != nil {
		out.DS = append([]AnchorDS(nil), a.DS...)
	}
	if a.DNSKEYs != nil {
		out.DNSKEYs = append([]AnchorDNSKEY(nil), a.DNSKEYs...)
	}
	return out
}

// builtinRootAnchors holds the IANA-issued root-zone DS records embedded
// at compile time. Kept unexported to prevent accidental mutation;
// callers receive a defensive copy from [BuiltinRootAnchors].
//
//	Key Tag 20326 — Root KSK-2017 (active since 2017-02-02)
//	Key Tag 38696 — Root KSK-2024 (active since 2024-07-18)
//
// Sourced from <https://data.iana.org/root-anchors/root-anchors.xml>.
// DNSKEY records are intentionally empty; the chain validator fetches
// the live root DNSKEY via DoH at validation time and authenticates it
// against these DS digests.
var builtinRootAnchors = RootAnchors{
	LastUpdated: "2024-11-05",
	Source:      "builtin",
	DS: []AnchorDS{
		{
			KeyTag:     20326,
			Algorithm:  8, // RSASHA256
			DigestType: 2, // SHA-256
			Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		},
		{
			KeyTag:     38696,
			Algorithm:  8, // RSASHA256
			DigestType: 2, // SHA-256
			Digest:     "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
		},
	},
	DNSKEYs: nil,
}

// BuiltinRootAnchors returns a fresh copy of the IANA-issued built-in
// trust anchors (KSK-2017 + KSK-2024). Each call yields an independent
// value so the caller may mutate it freely.
func BuiltinRootAnchors() *RootAnchors {
	return builtinRootAnchors.Clone()
}

// ReadAnchors decodes a JSON [RootAnchors] document from r. The on-disk
// format is shared with dnsdata-js. Returns a wrapped [ErrAnchors] on
// parse failure.
func ReadAnchors(r io.Reader) (*RootAnchors, error) {
	var a RootAnchors
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAnchors, err)
	}
	return &a, nil
}

// WriteAnchors emits a [RootAnchors] document to w as indented JSON,
// using the same field order and casing as dnsdata-js.
func WriteAnchors(w io.Writer, a *RootAnchors) error {
	if a == nil {
		return fmt.Errorf("%w: nil anchors", ErrAnchors)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		return fmt.Errorf("%w: %v", ErrAnchors, err)
	}
	return nil
}

// DefaultAnchorsPath returns the conventional location for caller-supplied
// trust anchors (`~/.dnsdata/root-anchors.json`). Shared with dnsdata-js
// so the same file is honoured by both sibling implementations.
//
// This function does NOT touch the filesystem; it only computes the path.
// Callers wishing to load anchors must open the file themselves and pass
// the reader to [ReadAnchors] — keeping this package free of implicit
// filesystem effects per MUST NOT 23 in DESIGN.md.
func DefaultAnchorsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAnchors, err)
	}
	return filepath.Join(home, ".dnsdata", "root-anchors.json"), nil
}
