package verifier_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/types"
)

// TestValidate_DNSKEYOutsideDNSKEYAnswer: a DNSKEY for the zone carried
// in the answer to some other query arrives after the zone's DNSKEY
// rrset was authenticated. It must not become a signing key of the
// zone.
func TestValidate_DNSKEYOutsideDNSKEYAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, qname string
		qtype       uint16
	}{
		{"leaf answer", "evil.example.com.", types.TypeA},
		{"DS answer", "evil.example.com.", types.TypeDS}, // asked of example.com.
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newKeyAuthChain(t, 257, 257)
			attacker := newSignedZone(t, "example.com.", c.inception, c.expire)
			attacker.addSignedRR(t, "evil.example.com.", 300, types.TypeA, "203.0.113.66", c.inception, c.expire)
			resp := c.responses()
			resp[lookupKey{"evil.example.com.", types.TypeA}] = rrsetWithSigs(attacker.z, "evil.example.com.", types.TypeA)
			k := lookupKey{tc.qname, tc.qtype}
			resp[k] = append(resp[k], attacker.z.FindRRSet("example.com.", types.TypeDNSKEY)...)

			res := c.validate(t, resp, "evil.example.com.")
			wantBogus(t, res, "example.com.")
		})
	}
}
