package verifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
)

// buildChain signs everything from now-1h to now+24h. A clock outside
// that window must turn a Secure chain into Bogus (RFC 4035 §5.3.1).
func TestValidate_ClockOutsideValidityIsBogus(t *testing.T) {
	cases := []struct {
		name  string
		clock time.Time
		want  verifier.Verdict
	}{
		{"inside window", time.Now(), verifier.VerdictSecure},
		{"after expiration", time.Now().Add(48 * time.Hour), verifier.VerdictBogus},
		{"before inception", time.Now().Add(-48 * time.Hour), verifier.VerdictBogus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver, anchors := buildChain(t)
			v, err := verifier.NewVerifier(
				verifier.WithResolver(resolver),
				verifier.WithTrustAnchors(anchors),
				verifier.WithClock(func() time.Time { return tc.clock }),
			)
			if err != nil {
				t.Fatal(err)
			}
			res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if res.Verdict != tc.want {
				t.Errorf("Verdict = %v (%s at %s), want %v", res.Verdict, res.BogusReason, res.BogusAt, tc.want)
			}
		})
	}
}
