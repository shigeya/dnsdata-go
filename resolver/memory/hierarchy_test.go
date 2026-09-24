package memory_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/zone"
)

var (
	inception  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiration = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	now        = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
)

// bindPrivateText is a BIND K*.private file for the deterministic P-256
// key derived from seed.
func bindPrivateText(seed string) string {
	d := sha256.Sum256([]byte(seed))
	return "Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: " +
		base64.StdEncoding.EncodeToString(d[:]) + "\n"
}

// fixedKey loads the deterministic P-256 key derived from seed.
func fixedKey(t testing.TB, owner, seed string, flags uint16) *signer.Key {
	t.Helper()
	k, err := signer.ParseBINDPrivate(owner, flags, []byte(bindPrivateText(seed)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// hierarchy is a signed fake root, test., and example.test.
type hierarchy struct {
	root, tld, leaf *zone.Zone
	rootKSK         *signer.Key
	leafKeys        []*signer.Key
	leafUnsigned    *zone.Zone
}

func readZone(t testing.TB, text string) *zone.Zone {
	t.Helper()
	zone.RegisterHandlers()
	dnssec.RegisterHandlers()
	var z zone.Zone
	if err := z.ReadStringStrict(text); err != nil {
		t.Fatal(err)
	}
	return &z
}

func ds(t testing.TB, k *signer.Key) string {
	t.Helper()
	v, err := k.DS(signer.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func sign(t testing.TB, z *zone.Zone, apex string, keys []*signer.Key, from, until time.Time) *zone.Zone {
	t.Helper()
	signed, err := signer.SignZone(z, apex, keys, signer.Options{Inception: from, Expiration: until})
	if err != nil {
		t.Fatalf("SignZone(%s): %v", apex, err)
	}
	return signed
}

const leafText = `$ORIGIN example.test.
$TTL 3600
@      SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@      NS  ns1.example.test.
ns1    A   192.0.2.1
www    A   192.0.2.10
www    TXT "hello"
key    TYPE65400 \# 35 030101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
*.wild A   192.0.2.20
alias  CNAME www.example.test.
`

// hierarchyKeys are the fixed keys of the hierarchy; the seed also
// names the key file in testdata/signed/keys.
var hierarchyKeys = []struct {
	owner, seed string
	flags       uint16
}{
	{".", "root-ksk", signer.FlagsKSK},
	{"test.", "test-ksk", signer.FlagsKSK},
	{"example.test.", "example-ksk", signer.FlagsKSK},
	{"example.test.", "example-zsk", signer.FlagsZSK},
}

func buildHierarchy(t testing.TB) *hierarchy {
	t.Helper()
	keys := make([]*signer.Key, len(hierarchyKeys))
	for i, k := range hierarchyKeys {
		keys[i] = fixedKey(t, k.owner, k.seed, k.flags)
	}
	rootKSK, tldKSK, leafKSK, leafZSK := keys[0], keys[1], keys[2], keys[3]

	root := readZone(t, `. 86400 SOA a.root.test. hostmaster.root.test. 1 1800 900 604800 86400
. 86400 NS a.root.test.
test. 86400 NS ns.test.
test. 86400 DS `+ds(t, tldKSK)+"\n")
	tld := readZone(t, `$ORIGIN test.
$TTL 3600
@ SOA ns.test. hostmaster.test. 1 7200 3600 1209600 300
@ NS ns.test.
ns A 192.0.2.53
example NS ns1.example.test.
example DS `+ds(t, leafKSK)+`
insecure NS ns.insecure.test.
ns.insecure A 192.0.2.54
`)
	leaf := readZone(t, leafText)
	leafKeys := []*signer.Key{leafKSK, leafZSK}
	return &hierarchy{
		root:         sign(t, root, ".", []*signer.Key{rootKSK}, inception, expiration),
		tld:          sign(t, tld, "test.", []*signer.Key{tldKSK}, inception, expiration),
		leaf:         sign(t, leaf, "example.test.", leafKeys, inception, expiration),
		rootKSK:      rootKSK,
		leafKeys:     leafKeys,
		leafUnsigned: leaf,
	}
}
