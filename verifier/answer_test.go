package verifier_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
)

func TestValidate_AnswerCarriesTheValidatedRRset(t *testing.T) {
	resolver, anchors := buildChain(t)
	v, err := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors))
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Validate(context.Background(), "www.example.com.", types.TypeA)
	if err != nil || res.Verdict != verifier.VerdictSecure {
		t.Fatalf("Validate = %v, %v", res.Verdict, err)
	}
	a := res.Answer
	if a == nil {
		t.Fatal("Answer is nil for a Secure positive answer")
	}
	if a.Name != "www.example.com." || a.Type != types.TypeA || len(a.Records) != 1 {
		t.Fatalf("Answer = %+v", a)
	}
	rec := a.Records[0]
	if rec.Value != "192.0.2.10" || rec.TTL != 300 || !bytes.Equal(rec.RData, []byte{192, 0, 2, 10}) {
		t.Errorf("record = %+v", rec)
	}
	if len(a.Signatures) != 1 {
		t.Fatalf("Signatures = %+v, want the one RRSIG that verified", a.Signatures)
	}
	sig := a.Signatures[0]
	if sig.Signer != "example.com." || sig.Algorithm != 13 || sig.KeyTag == 0 {
		t.Errorf("signature = %+v", sig)
	}
	if !sig.Inception.Before(time.Now()) || !sig.Expiration.After(time.Now()) || sig.Inception.Location() != time.UTC {
		t.Errorf("signature window %v .. %v", sig.Inception, sig.Expiration)
	}

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back verifier.Result
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Answer == nil || !bytes.Equal(back.Answer.Records[0].RData, rec.RData) || !back.Answer.Signatures[0].Expiration.Equal(sig.Expiration) {
		t.Errorf("JSON round trip lost the answer: %s", raw)
	}
}

func TestValidate_NoAnswerUnlessSecure(t *testing.T) {
	resolver, anchors := buildChain(t)
	cases := []struct {
		name  string
		clock time.Time
		qname string
	}{
		{"bogus (expired)", time.Now().Add(48 * time.Hour), "www.example.com."},
		{"no records", time.Now(), "missing.example.com."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := verifier.NewVerifier(verifier.WithResolver(resolver), verifier.WithTrustAnchors(anchors),
				verifier.WithClock(func() time.Time { return tc.clock }))
			res, err := v.Validate(context.Background(), tc.qname, types.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict == verifier.VerdictSecure || res.Answer != nil {
				t.Errorf("Verdict %v, Answer %+v; want no answer", res.Verdict, res.Answer)
			}
			raw, _ := json.Marshal(res)
			if bytes.Contains(raw, []byte(`"answer"`)) {
				t.Errorf("JSON carries an empty answer: %s", raw)
			}
		})
	}
}
