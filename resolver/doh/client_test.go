package doh_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/resolver/doh"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// stubResponse is what the mock server returns on success. The bytes
// are not a valid DNS message — the doh package returns them as-is and
// leaves parsing to a higher layer (the chain validator, Week 3).
var stubResponse = []byte{
	0x12, 0x34, // ID
	0x81, 0x80, // flags (QR=1, RD=1, RA=1)
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT (will be 0 in this stub)
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
}

// newStubProvider returns a server that responds with stubResponse on
// every POST to any path, plus its URL.
func newStubProvider(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != doh.MediaType {
			http.Error(w, "content-type", http.StatusUnsupportedMediaType)
			return
		}
		// Drain the body so the real request bytes don't break later
		// inspection. We don't validate them here; that's BuildQuery's
		// concern.
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", doh.MediaType)
		_, _ = w.Write(stubResponse)
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

func newClient(opts ...doh.Option) *doh.Client {
	return doh.NewClient(append(opts, doh.WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))...)
}

func TestClient_Query_ReturnsResponseBytes(t *testing.T) {
	_, url := newStubProvider(t)
	c := newClient(doh.WithProviders(url))
	out, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(out, stubResponse) {
		t.Errorf("response mismatch: got % x want % x", out, stubResponse)
	}
}

func TestClient_QueryRaw_FailsOver(t *testing.T) {
	// First provider always 500s; second succeeds.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	_, good := newStubProvider(t)

	c := newClient(doh.WithProviders(bad.URL, good))
	out, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(out, stubResponse) {
		t.Errorf("response mismatch")
	}
}

func TestClient_QueryRaw_AllProvidersFail(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	c := newClient(doh.WithProviders(bad.URL, bad.URL))

	_, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, doh.ErrAllProvidersFailed) {
		t.Errorf("err = %v, want ErrAllProvidersFailed", err)
	}
	if !errors.Is(err, doh.ErrUnexpectedStatus) {
		t.Errorf("err = %v, want ErrUnexpectedStatus wrapped inside", err)
	}
}

func TestClient_WithProvidersEmptyNormalisesToDefaults(t *testing.T) {
	c := newClient(doh.WithProviders())
	if got := len(c.Providers()); got != 3 {
		t.Errorf("Providers count = %d, want 3 (defaults)", got)
	}
}

func TestClient_QueryRaw_EmptyQueryBytes(t *testing.T) {
	_, url := newStubProvider(t)
	c := newClient(doh.WithProviders(url))
	// Sending zero-length query bytes is valid at the HTTP layer; the
	// stub server returns stubResponse anyway.
	out, err := c.QueryRaw(context.Background(), nil)
	if err != nil {
		t.Fatalf("QueryRaw: %v", err)
	}
	if !bytes.Equal(out, stubResponse) {
		t.Errorf("response mismatch")
	}
}

func TestClient_Query_UnexpectedContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not dns"))
	}))
	t.Cleanup(srv.Close)
	c := newClient(doh.WithProviders(srv.URL))

	_, err := c.Query(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, doh.ErrUnexpectedContentType) {
		t.Errorf("err = %v, want ErrUnexpectedContentType wrapped", err)
	}
}

func TestClient_Query_InvalidQName(t *testing.T) {
	_, url := newStubProvider(t)
	c := newClient(doh.WithProviders(url))
	tooLong := strings.Repeat("a", 70)
	_, err := c.Query(context.Background(), tooLong+".example.com.", types.TypeA)
	if !errors.Is(err, wire.ErrInvalidQName) {
		t.Errorf("err = %v, want wire.ErrInvalidQName wrapped", err)
	}
}

func TestClient_Query_ContextCancel(t *testing.T) {
	// Server holds the request open until the client gives up. Capped
	// at 1s as a safety net so a misbehaving HTTP layer can't stall
	// CI; the real assertion is that the client errors before then.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(1 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	c := newClient(doh.WithProviders(srv.URL))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.Query(ctx, "example.com.", types.TypeA)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected context-cancel error, got nil")
	}
	if !errors.Is(err, doh.ErrAllProvidersFailed) {
		t.Errorf("err = %v, want ErrAllProvidersFailed wrapper", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Query took %v, want fast cancel under 500ms", elapsed)
	}
}

func TestDefaultProviders_IsCopy(t *testing.T) {
	a := doh.DefaultProviders()
	a[0] = "https://example.invalid/dns-query"
	b := doh.DefaultProviders()
	if b[0] == a[0] {
		t.Errorf("DefaultProviders leaked mutation")
	}
}
