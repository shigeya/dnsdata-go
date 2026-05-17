package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// --- Test fixture helpers ------------------------------------------------

// signedZone is a synthetic DNS zone: one CSK that signs every rrset
// in the zone, plus the records themselves. Used as a building block
// for multi-level chain fixtures.
type signedZone struct {
	name string
	z    *dnssec.Zone
	key  *dnssec.DNSKey
}

// newSignedZone produces a fresh dnssec.Zone with one ECDSA-P256 CSK
// installed at name. The DNSKEY rrset is self-signed.
func newSignedZone(t *testing.T, name string, inception, expire int64) *signedZone {
	t.Helper()
	dnssec.RegisterHandlers()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey for %s: %v", name, err)
	}
	keyData := encodeECDSAP256Coords(t, &priv.PublicKey)
	value := "257 3 13 " + base64.StdEncoding.EncodeToString(keyData)

	z := dnssec.NewZone()
	dnskeyRR, err := z.AddRRFromParts(name, 3600, "IN", "DNSKEY", value)
	if err != nil {
		t.Fatalf("AddRR DNSKEY at %s: %v", name, err)
	}
	key := dnskeyRR.Handler().(*dnssec.DNSKey)
	key.SetPrivateKey(priv)

	rrsig, err := z.SignRR(name, 3600, types.TypeDNSKEY, key, inception, expire)
	if err != nil || rrsig == nil {
		t.Fatalf("SignRR DNSKEY at %s: %v", name, err)
	}
	z.AddRR(rrsig)

	return &signedZone{name: name, z: z, key: key}
}

// addRR adds a record to s and (when the type is signable here)
// signs it with s.key.
func (s *signedZone) addSignedRR(t *testing.T, owner string, ttl uint32, qtype uint16, value string, inception, expire int64) {
	t.Helper()
	typeName, err := types.RRTypeToString(qtype)
	if err != nil {
		t.Fatalf("RRTypeToString(%d): %v", qtype, err)
	}
	if _, err := s.z.AddRRFromParts(owner, ttl, "IN", typeName, value); err != nil {
		t.Fatalf("AddRR %s/%s: %v", owner, typeName, err)
	}
	rrsig, err := s.z.SignRR(owner, ttl, qtype, s.key, inception, expire)
	if err != nil || rrsig == nil {
		t.Fatalf("SignRR %s/%s: %v", owner, typeName, err)
	}
	s.z.AddRR(rrsig)
}

// addAndSignDS inserts a DS record for childKey at childName into the
// parent zone, then signs the DS rrset with the parent's CSK.
func addAndSignDS(t *testing.T, parent *signedZone, childName string, childKey *dnssec.DNSKey, inception, expire int64) {
	t.Helper()
	digestInput, err := childKey.DSDigestData()
	if err != nil {
		t.Fatalf("DSDigestData for %s: %v", childName, err)
	}
	sum := sha256.Sum256(digestInput)
	dsValue := joinSpace(
		decUint(childKey.KeyTag),
		decUint(childKey.Algorithm),
		"2",
		hex.EncodeToString(sum[:]),
	)
	parent.addSignedRR(t, childName, 3600, types.TypeDS, dsValue, inception, expire)
}

// rrsetWithSigs returns every record at (name, qtype) plus every
// RRSIG record at name that covers qtype. Used to feed the mock
// resolver.
func rrsetWithSigs(z *dnssec.Zone, name string, qtype uint16) []*zone.ResourceRecord {
	out := append([]*zone.ResourceRecord(nil), z.FindRRSet(name, qtype)...)
	for _, rr := range z.FindRRSet(name, types.TypeRRSIG) {
		h, ok := rr.Handler().(*dnssec.RRSig)
		if !ok {
			continue
		}
		if h.TypeCovered == qtype {
			out = append(out, rr)
		}
	}
	return out
}

// makeTrustAnchor returns a RootAnchors with one DS entry pointing at
// rootKey, hashed with SHA-256.
func makeTrustAnchor(t *testing.T, rootKey *dnssec.DNSKey) *dnssec.RootAnchors {
	t.Helper()
	digestInput, err := rootKey.DSDigestData()
	if err != nil {
		t.Fatalf("DSDigestData(root): %v", err)
	}
	sum := sha256.Sum256(digestInput)
	return &dnssec.RootAnchors{
		LastUpdated: "test",
		Source:      "test-fixture",
		DS: []dnssec.AnchorDS{{
			KeyTag:     rootKey.KeyTag,
			Algorithm:  rootKey.Algorithm,
			DigestType: 2,
			Digest:     strings.ToUpper(hex.EncodeToString(sum[:])),
		}},
	}
}

// mockResolver returns preloaded records for a fixed (name, qtype)
// map. Names compare case-insensitively to match what the verifier
// normalises.
type mockResolver struct {
	responses map[lookupKey][]*zone.ResourceRecord
	errOnce   map[string]error // name → error returned on first lookup, then cleared
}

type lookupKey struct {
	name  string
	qtype uint16
}

func (r *mockResolver) Query(ctx context.Context, name string, qtype uint16) ([]*zone.ResourceRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.errOnce != nil {
		if err, ok := r.errOnce[name]; ok {
			delete(r.errOnce, name)
			return nil, err
		}
	}
	name = strings.ToLower(name)
	return r.responses[lookupKey{name: name, qtype: qtype}], nil
}

// buildChain wires three signed zones — root, com., example.com. —
// with delegations between them and signs a leaf A record. Returns
// the mock resolver and the trust anchors for the verifier.
func buildChain(t *testing.T) (*mockResolver, *dnssec.RootAnchors) {
	t.Helper()
	inception := time.Now().Add(-1 * time.Hour).Unix()
	expire := time.Now().Add(24 * time.Hour).Unix()

	root := newSignedZone(t, ".", inception, expire)
	com := newSignedZone(t, "com.", inception, expire)
	leaf := newSignedZone(t, "example.com.", inception, expire)

	addAndSignDS(t, root, "com.", com.key, inception, expire)
	addAndSignDS(t, com, "example.com.", leaf.key, inception, expire)

	leaf.addSignedRR(t, "www.example.com.", 300, types.TypeA, "192.0.2.10", inception, expire)
	leaf.addSignedRR(t, "example.com.", 300, types.TypeA, "192.0.2.1", inception, expire)

	resp := map[lookupKey][]*zone.ResourceRecord{
		{".", types.TypeDNSKEY}:               rrsetWithSigs(root.z, ".", types.TypeDNSKEY),
		{"com.", types.TypeDS}:                rrsetWithSigs(root.z, "com.", types.TypeDS),
		{"com.", types.TypeDNSKEY}:            rrsetWithSigs(com.z, "com.", types.TypeDNSKEY),
		{"example.com.", types.TypeDS}:        rrsetWithSigs(com.z, "example.com.", types.TypeDS),
		{"example.com.", types.TypeDNSKEY}:    rrsetWithSigs(leaf.z, "example.com.", types.TypeDNSKEY),
		{"example.com.", types.TypeA}:         rrsetWithSigs(leaf.z, "example.com.", types.TypeA),
		{"www.example.com.", types.TypeA}:     rrsetWithSigs(leaf.z, "www.example.com.", types.TypeA),
		{"www.example.com.", types.TypeDS}:    nil, // not a zone cut
	}
	return &mockResolver{responses: resp}, makeTrustAnchor(t, root.key)
}

// --- Tests ---------------------------------------------------------------

func TestValidate_Secure_LeafRecord(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, err := verifier.NewVerifier(
		verifier.WithResolver(resolver),
		verifier.WithTrustAnchors(anchors),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure (Bogus at=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
	if len(res.Chain) != 3 {
		t.Errorf("Chain length = %d, want 3 (root, com., example.com.)", len(res.Chain))
	}
	// Evidence is populated.
	if len(res.Evidence.DNSKEYs) == 0 || len(res.Evidence.DSes) == 0 || len(res.Evidence.RRSIGs) == 0 {
		t.Errorf("Evidence not populated: %+v", res.Evidence)
	}
}

func TestValidate_Secure_ApexRecord(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	res, err := v.Validate(context.Background(), "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictSecure {
		t.Errorf("Verdict = %s, want secure (Bogus at=%q reason=%q)", res.Verdict, res.BogusAt, res.BogusReason)
	}
}

func TestValidate_TrustAnchorMismatch(t *testing.T) {
	resolver, _ := buildChain(t)
	// Anchor with the right tag/algorithm but a garbage digest.
	bogusAnchors := &dnssec.RootAnchors{
		Source: "wrong",
		DS: []dnssec.AnchorDS{{
			KeyTag:     1,
			Algorithm:  13,
			DigestType: 2,
			Digest:     strings.Repeat("00", 32),
		}},
	}
	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(bogusAnchors))
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
	if res.BogusAt != "." {
		t.Errorf("BogusAt = %q, want '.'", res.BogusAt)
	}
}

func TestValidate_BogusLeafSignature(t *testing.T) {
	resolver, anchors := buildChain(t)
	key := lookupKey{"www.example.com.", types.TypeA}
	if len(resolver.responses[key]) < 2 {
		t.Fatal("expected at least one A record + one RRSIG in fixture")
	}
	// Flip a byte in the cached RRSIG handler's Signature so the next
	// signature check fails. Touching rr.Value would only update the
	// textual form; the resolver returns records whose handler is
	// already constructed.
	for _, rr := range resolver.responses[key] {
		if rr.Type != types.TypeRRSIG {
			continue
		}
		sig := rr.Handler().(*dnssec.RRSig)
		sig.Signature[0] ^= 0x01
		break
	}

	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verifier.VerdictBogus {
		t.Errorf("Verdict = %s, want bogus", res.Verdict)
	}
}

func TestValidate_Indeterminate_OnResolverError(t *testing.T) {
	resolver, anchors := buildChain(t)
	resolver.errOnce = map[string]error{".": errors.New("simulated upstream failure")}
	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if !errors.Is(err, verifier.ErrResolver) {
		t.Errorf("err = %v, want ErrResolver", err)
	}
	if res.Verdict != verifier.VerdictIndeterminate {
		t.Errorf("Verdict = %s, want indeterminate", res.Verdict)
	}
}

func TestValidate_ChainTimeout(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled context
	_, err := v.Validate(ctx, "www.example.com.", types.TypeA)
	if !errors.Is(err, verifier.ErrChainTimeout) {
		t.Errorf("err = %v, want ErrChainTimeout", err)
	}
}

func TestNewVerifier_RequiresResolver(t *testing.T) {
	_, err := verifier.NewVerifier()
	if !errors.Is(err, verifier.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}

func TestVerdict_JSONRoundTrip(t *testing.T) {
	for _, v := range []verifier.Verdict{
		verifier.VerdictSecure, verifier.VerdictInsecure,
		verifier.VerdictBogus, verifier.VerdictIndeterminate,
	} {
		b, err := v.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON(%s): %v", v, err)
		}
		var got verifier.Verdict
		if err := got.UnmarshalJSON(b); err != nil {
			t.Fatalf("UnmarshalJSON: %v", err)
		}
		if got != v {
			t.Errorf("round-trip: got %s, want %s", got, v)
		}
	}
}

// --- Tiny utilities (kept local so the package doesn't ship them) ---

func encodeECDSAP256Coords(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	ek, err := pub.ECDH()
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	raw := ek.Bytes()
	if len(raw) != 65 || raw[0] != 0x04 {
		t.Fatalf("unexpected ECDH bytes: len=%d prefix=0x%02x", len(raw), raw[0])
	}
	return raw[1:]
}

func decUint[T uint8 | uint16 | uint32](v T) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	n := uint64(v)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

func joinSpace(parts ...string) string {
	return strings.Join(parts, " ")
}
