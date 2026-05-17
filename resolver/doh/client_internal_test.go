package doh

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// White-box test for the ErrNoProviders branch: WithProviders("") would
// normalise to defaults, so the only way to reach the empty-list code
// path from a configured Client is to wipe the slice directly. Doing
// that requires same-package access — hence this file lives inside the
// doh package itself.
func TestClient_QueryRaw_NoProviders(t *testing.T) {
	c := NewClient(WithHTTPClient(&http.Client{Timeout: time.Second}))
	c.providers = nil // bypass the WithProviders("") normalisation
	_, err := c.QueryRaw(context.Background(), []byte{0x00})
	if !errors.Is(err, ErrNoProviders) {
		t.Errorf("err = %v, want ErrNoProviders", err)
	}
}

func TestClient_DefaultUserAgent(t *testing.T) {
	c := NewClient()
	if c.userAgent != "dnsdata-go/doh" {
		t.Errorf("default User-Agent = %q", c.userAgent)
	}
	c2 := NewClient(WithUserAgent("test-ua/1.0"))
	if c2.userAgent != "test-ua/1.0" {
		t.Errorf("WithUserAgent: got %q", c2.userAgent)
	}
}
