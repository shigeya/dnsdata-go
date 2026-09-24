package memory_test

import (
	"context"
	"fmt"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/dnssec/signer"
	"github.com/shigeya/dnsdata-go/resolver/memory"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// Example validates a name under a private root: sign "." → "test." →
// "example.test.", serve the three zones from memory, and make the
// root's KSK the verifier's trust anchor. Nothing touches the network
// or the real root.
func Example() {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := signer.Options{Inception: from, Expiration: from.AddDate(1, 0, 0)}

	rootKey, _ := signer.GenerateKey(".", types.AlgoECDSAP256SHA256, signer.FlagsKSK)
	tldKey, _ := signer.GenerateKey("test.", types.AlgoECDSAP256SHA256, signer.FlagsKSK)
	leafKey, _ := signer.GenerateKey("example.test.", types.AlgoECDSAP256SHA256, signer.FlagsKSK)
	tldDS, _ := tldKey.DS(signer.DigestSHA256)
	leafDS, _ := leafKey.DS(signer.DigestSHA256)

	dnssec.RegisterHandlers() // the strict reader needs the DS encoder
	build := func(apex, text string, key *signer.Key) *zone.Zone {
		var z zone.Zone
		if err := z.ReadStringStrict(text); err != nil {
			panic(err)
		}
		signed, err := signer.SignZone(&z, apex, []*signer.Key{key}, opts)
		if err != nil {
			panic(err)
		}
		return signed
	}
	root := build(".", ". 86400 NS a.root.test.\ntest. 86400 NS ns.test.\ntest. 86400 DS "+tldDS+"\n", rootKey)
	tld := build("test.", "test. 3600 NS ns.test.\nexample.test. 3600 NS ns.example.test.\nexample.test. 3600 DS "+leafDS+"\n", tldKey)
	leaf := build("example.test.", "example.test. 3600 NS ns.example.test.\nwww.example.test. 3600 A 192.0.2.10\n", leafKey)

	auth, _ := memory.New(
		memory.WithZone(".", root),
		memory.WithZone("test.", tld),
		memory.WithZone("example.test.", leaf),
	)
	anchors, _ := signer.RootAnchors(rootKey)
	v, _ := verifier.NewVerifier(
		verifier.WithResolver(auth),
		verifier.WithTrustAnchors(anchors),
		verifier.WithClock(func() time.Time { return from.AddDate(0, 6, 0) }),
	)
	for _, q := range []struct {
		name  string
		qtype uint16
	}{{"www.example.test.", types.TypeA}, {"www.example.test.", types.TypeMX}, {"nope.example.test.", types.TypeA}} {
		res, _ := v.Validate(context.Background(), q.name, q.qtype)
		fmt.Println(q.name, types.RRTypeName(q.qtype), res.Verdict)
	}
	// Output:
	// www.example.test. A secure
	// www.example.test. MX secure-nodata
	// nope.example.test. A secure-nxdomain
}
