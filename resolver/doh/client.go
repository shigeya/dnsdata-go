package doh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shigeya/dnsdata-go/wire"
)

// Default DoH provider endpoints, used in the order shown when
// [NewClient] is called without [WithProviders].
const (
	DefaultGoogle     = "https://dns.google/dns-query"
	DefaultCloudflare = "https://cloudflare-dns.com/dns-query"
	DefaultQuad9      = "https://dns.quad9.net/dns-query"
)

// MediaType is the MIME type defined by RFC 8484 §6 for DoH messages.
const MediaType = "application/dns-message"

// DefaultProviders returns a fresh copy of the default provider list
// in the order [Client] tries them: Cloudflare → Google → Quad9. Each
// call yields an independent slice so the caller may freely mutate the
// result.
//
// The order is chosen for tail-latency stability rather than for any
// single-region peak speed. See the package doc for the rationale and
// for guidance on overriding it.
func DefaultProviders() []string {
	return []string{DefaultCloudflare, DefaultGoogle, DefaultQuad9}
}

// Client is a DoH resolver with provider failover. The zero value is
// not usable; build one with [NewClient].
//
// A Client is safe for concurrent use by multiple goroutines: every
// field is immutable after construction.
type Client struct {
	httpClient *http.Client
	providers  []string
	userAgent  string
}

// Option configures a [Client] at construction time.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client used to send DoH requests.
// Useful in tests (httptest.Server backed transport) and for callers
// who want a shared transport pool with custom TLS / proxy settings.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithProviders sets the provider URLs to try in order. An empty list
// is normalised to the default set.
func WithProviders(urls ...string) Option {
	return func(c *Client) {
		if len(urls) == 0 {
			c.providers = DefaultProviders()
			return
		}
		c.providers = append([]string(nil), urls...)
	}
}

// WithUserAgent overrides the User-Agent header sent on each request.
// Defaults to "dnsdata-go/doh".
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// NewClient constructs a [Client] with the supplied options. A default
// HTTP client (10s timeout, no proxy beyond the environment) is used
// when none is supplied.
func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		providers:  DefaultProviders(),
		userAgent:  "dnsdata-go/doh",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Providers returns a fresh copy of the configured provider list.
func (c *Client) Providers() []string {
	return append([]string(nil), c.providers...)
}

// Query issues a DoH query for (qname, qtype) with class IN and the DO
// bit set. The response is the raw DNS message bytes from the first
// provider that succeeds.
func (c *Client) Query(ctx context.Context, qname string, qtype uint16) ([]byte, error) {
	query, err := wire.BuildQuery(qname, qtype)
	if err != nil {
		return nil, err
	}
	return c.QueryRaw(ctx, query)
}

// QueryRaw sends a prebuilt DNS query message via DoH and returns the
// response bytes from the first provider that succeeds.
//
// Failover policy: the providers are tried in registration order.
// Network errors and non-2xx responses are treated as failover
// triggers; a 2xx response with the right Content-Type is returned
// immediately even when the embedded DNS RCODE is non-zero (that is a
// DNS-level error, not a transport-level one).
func (c *Client) QueryRaw(ctx context.Context, query []byte) ([]byte, error) {
	if len(c.providers) == 0 {
		return nil, ErrNoProviders
	}

	var firstErr error
	for _, url := range c.providers {
		resp, err := c.sendOne(ctx, url, query)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return resp, nil
	}
	if firstErr == nil {
		// Defensive: providers list was non-empty but every iteration
		// produced neither a response nor an error.
		return nil, ErrAllProvidersFailed
	}
	// Join so errors.Is satisfies both the umbrella ErrAllProvidersFailed
	// and the inner sentinel (ErrUnexpectedStatus / ErrDoH / ...) that
	// the first provider produced.
	return nil, errors.Join(ErrAllProvidersFailed, firstErr)
}

// sendOne performs one HTTP POST against url. Returned errors all
// wrap [ErrDoH] (often along with a more specific sentinel).
func (c *Client) sendOne(ctx context.Context, url string, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrDoH, err)
	}
	req.Header.Set("Content-Type", MediaType)
	req.Header.Set("Accept", MediaType)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: post %s: %v", ErrDoH, url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a few bytes so the connection can be reused, but
		// don't load arbitrary upstream errors into memory.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil, fmt.Errorf("%w: %s returned HTTP %d", ErrUnexpectedStatus, url, resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	// Tolerate parameters such as `application/dns-message; charset=utf-8`
	// by matching only the media-type prefix.
	if !strings.HasPrefix(ct, MediaType) {
		return nil, fmt.Errorf("%w: %s returned %q", ErrUnexpectedContentType, url, ct)
	}

	// RFC 8484 §4.2.1 caps response sizes implicitly at the EDNS UDP
	// size we requested (4096) plus headroom; cap at 64 KiB defensively.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrDoH, err)
	}
	return body, nil
}

