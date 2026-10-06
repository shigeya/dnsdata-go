package verifier_test

import (
	"testing"

	"github.com/shigeya/dnsdata-go/verifier"
)

// TestZoneStep_DSDigests checks that each step below the root lists the
// DS records that authorised the descent into it (they live in the
// parent's response, not the child's).
func TestZoneStep_DSDigests(t *testing.T) {
	f := newReasonFixture(t)
	res, err := f.validate(t, "www.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint16{"com.": f.com.key.KeyTag, "example.com.": f.leaf.key.KeyTag}
	for _, step := range res.Chain {
		tag, below := want[step.Zone]
		if !below {
			if len(step.DSDigests) != 0 {
				t.Errorf("%s: DSDigests %+v, want none", step.Zone, step.DSDigests)
			}
			continue
		}
		if len(step.DSDigests) != 1 || step.DSDigests[0] != (verifier.DSSummary{KeyTag: tag, Algorithm: 13, DigestType: 2}) {
			t.Errorf("%s: DSDigests %+v, want one for key %d", step.Zone, step.DSDigests, tag)
		}
	}
}
