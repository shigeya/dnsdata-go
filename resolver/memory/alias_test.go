package memory_test

import (
	"context"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// aliasLeafText is example.test. with a wildcard CNAME and a DNAME. It
// is kept apart from leafText so the shared vectors in testdata/signed
// stay unchanged.
const aliasLeafText = `$ORIGIN example.test.
$TTL 3600
@        SOA   ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@        NS    ns1.example.test.
ns1      A     192.0.2.1
www      A     192.0.2.10
www      TXT   "hello"
*.wc     CNAME www.example.test.
old      DNAME new.example.test.
www.new  TXT   "moved"
`

func aliasLeaf(t *testing.T, h *hierarchy) *zone.Zone {
	t.Helper()
	return sign(t, readZone(t, aliasLeafText), "example.test.", h.leafKeys, inception, expiration)
}

func queryAliasLeaf(t *testing.T, h *hierarchy, qname string, qtype uint16) []*zone.ResourceRecord {
	t.Helper()
	resp, err := newAuthority(t, h, aliasLeaf(t, h)).Query(context.Background(), qname, qtype)
	if err != nil {
		t.Fatal(err)
	}
	if resp.RCode != 0 {
		t.Fatalf("RCode = %d, want NOERROR", resp.RCode)
	}
	return resp.Records
}

func findRR(records []*zone.ResourceRecord, owner string, rrtype uint16) *zone.ResourceRecord {
	for _, rr := range records {
		if rr.Label == owner && rr.Type == rrtype {
			return rr
		}
	}
	return nil
}

// RFC 4592 §3.3.3: a wildcard CNAME is synthesised for a query of any
// type, not only CNAME.
func TestAuthority_WildcardCNAMEForOtherTypes(t *testing.T) {
	h := buildHierarchy(t)
	records := queryAliasLeaf(t, h, "x.sub.wc.example.test.", types.TypeTXT)
	cname := findRR(records, "x.sub.wc.example.test.", types.TypeCNAME)
	if cname == nil || cname.Value != "www.example.test." {
		t.Fatalf("no synthesised CNAME at the query name: %v", records)
	}
	if findRR(records, "*.wc.example.test.", types.TypeNSEC) == nil {
		t.Errorf("no NSEC proving the next closer name: %v", records)
	}
}

// RFC 6672 §5.3.1: a DNAME answer carries the CNAME synthesised from it,
// owned by the query name, unsigned, with the DNAME's TTL.
func TestAuthority_DNAMECarriesSynthesisedCNAME(t *testing.T) {
	h := buildHierarchy(t)
	records := queryAliasLeaf(t, h, "www.old.example.test.", types.TypeTXT)
	if findRR(records, "old.example.test.", types.TypeDNAME) == nil {
		t.Fatalf("no DNAME: %v", records)
	}
	cname := findRR(records, "www.old.example.test.", types.TypeCNAME)
	if cname == nil || cname.Value != "www.new.example.test." || cname.TTL != 3600 {
		t.Fatalf("synthesised CNAME = %+v, want www.old → www.new with TTL 3600", cname)
	}
	for _, rr := range records {
		if rr.Type == types.TypeRRSIG && rr.Label == "www.old.example.test." {
			t.Errorf("synthesised CNAME is signed: %v", rr)
		}
	}
}

func TestHierarchy_AliasVerdicts(t *testing.T) {
	h := buildHierarchy(t)
	v := newVerifier(t, h, newAuthority(t, h, aliasLeaf(t, h)), now)
	cases := []struct {
		name, qname, aliasType, from, target string
	}{
		{"wildcard CNAME for another type", "x.sub.wc.example.test.", "cname", "x.sub.wc.example.test.", "www.example.test."},
		{"DNAME with the synthesised CNAME", "www.old.example.test.", "dname", "old.example.test.", "www.new.example.test."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := validate(t, v, tc.qname, types.TypeTXT)
			if res.Verdict != verifier.VerdictSecure {
				t.Fatalf("Verdict = %v (bogus %q at %q), want Secure", res.Verdict, res.BogusReason, res.BogusAt)
			}
			if len(res.Aliases) != 1 {
				t.Fatalf("Aliases = %+v, want one hop", res.Aliases)
			}
			if a := res.Aliases[0]; a.Type != tc.aliasType || a.From != tc.from || a.Target != tc.target {
				t.Errorf("alias = %+v, want %s %s → %s", a, tc.aliasType, tc.from, tc.target)
			}
		})
	}
}
