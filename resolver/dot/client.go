// Package dot is a DNS-over-TLS client (RFC 7858). Each query opens a
// TLS connection to a configured server, sends the query with the
// two-octet length framing of DNS over TCP (RFC 7858 §3.3), and reads
// one response. The server is authenticated as in the strict privacy
// profile of RFC 8310: its certificate must chain to a trusted root and
// match the server's name or address, and TLS is 1.2 or later.
//
// [Client.Resolve] returns a [resolver.Response] and satisfies
// verifier.ResolverFunc, like the auth and DoH clients:
//
//	c := dot.NewClient(dot.WithServers("1.1.1.1"))
//	v, _ := verifier.NewVerifier(verifier.WithResolver(verifier.ResolverFunc(c.Resolve)))
//
// Connections are not reused across queries.
package dot

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/shigeya/dnsdata-go/resolver"
	"github.com/shigeya/dnsdata-go/resolver/internal/message"
	"github.com/shigeya/dnsdata-go/resolver/internal/stream"
	"github.com/shigeya/dnsdata-go/wire"
)

// DefaultPort is the DNS-over-TLS port (RFC 7858 §3.1).
const DefaultPort = "853"

// DefaultTimeout caps one server attempt (TLS dial, handshake, query
// and response). The total budget is the caller's context.
const DefaultTimeout = 5 * time.Second

// headerLength is the fixed DNS message header.
const headerLength = 12

// Client speaks DNS over TLS. Build it with [NewClient]; it is safe for
// concurrent use, since nothing changes after construction.
type Client struct {
	servers   []string
	timeout   time.Duration
	tlsConfig *tls.Config
	queryOpts wire.QueryOptions
}

// Option configures a [Client] at construction time.
type Option func(*Client)

// WithServers sets the servers to try in order, each `host:port`, or a
// bare host for port 853 (see [NormalizeAddr]). The host is the name
// the certificate must match unless the TLS configuration names one.
func WithServers(addrs ...string) Option {
	return func(c *Client) {
		c.servers = make([]string, 0, len(addrs))
		for _, a := range addrs {
			c.servers = append(c.servers, NormalizeAddr(a))
		}
	}
}

// WithTLSConfig sets the TLS configuration, copied: RootCAs to trust a
// private CA, ServerName when the certificate names the server rather
// than the address dialed. A MinVersion below TLS 1.2 is raised.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *Client) { c.tlsConfig = cfg.Clone() }
}

// WithTimeout overrides the per-server timeout (default 5s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithCheckingDisabled sets the CD bit on every query (RFC 4035
// §3.2.2), so a validating server returns data it would reject as
// bogus instead of SERVFAIL. Off by default.
func WithCheckingDisabled(cd bool) Option {
	return func(c *Client) { c.queryOpts.CheckingDisabled = cd }
}

// NewClient constructs a Client. Without servers, queries return
// [ErrNoServers].
func NewClient(opts ...Option) *Client {
	c := &Client{timeout: DefaultTimeout}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Servers returns a fresh copy of the configured server list.
func (c *Client) Servers() []string {
	return append([]string(nil), c.servers...)
}

// Query sends a query for (qname, qtype) and returns the raw response
// from the first server that answers.
func (c *Client) Query(ctx context.Context, qname string, qtype uint16) ([]byte, error) {
	queryID := wire.RandomQueryID()
	msg, err := wire.BuildQueryWithOptions(queryID, qname, qtype, c.queryOpts)
	if err != nil {
		return nil, err
	}
	return c.QueryRaw(ctx, queryID, msg)
}

// QueryRaw sends a prebuilt query whose transaction ID is queryID and
// returns the response bytes. Servers are tried in order; when all
// fail, the error joins [ErrAllServersFailed] and the first failure.
func (c *Client) QueryRaw(ctx context.Context, queryID uint16, query []byte) ([]byte, error) {
	if len(c.servers) == 0 {
		return nil, ErrNoServers
	}
	var firstErr error
	for _, addr := range c.servers {
		resp, err := c.queryOne(ctx, addr, queryID, query)
		if err == nil {
			return resp, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, errors.Join(ErrAllServersFailed, firstErr)
}

// Resolve runs a query for (name, qtype) and returns the answer and
// authority records with the AD bit and RCODE. A non-zero RCODE is data,
// not an error; a response that does not parse is [ErrResolverResponse].
func (c *Client) Resolve(ctx context.Context, name string, qtype uint16) (resolver.Response, error) {
	raw, err := c.Query(ctx, name, qtype)
	if err != nil {
		return resolver.Response{}, err
	}
	resp, err := message.ToResponse(raw)
	if err != nil {
		return resolver.Response{}, fmt.Errorf("%w: %v", ErrResolverResponse, err)
	}
	return resp, nil
}

func (c *Client) queryOne(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Deadline: deadline}, Config: c.tlsConfigFor(addr)}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrDoT, addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: deadline %s: %v", ErrDoT, addr, err)
	}
	resp, err := stream.Exchange(conn, query)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDoT, addr, err)
	}
	if err := checkReply(resp, queryID); err != nil {
		return nil, err
	}
	return resp, nil
}

// tlsConfigFor returns the TLS configuration for one server: the
// configured one, naming the server's host when it names none, at TLS
// 1.2 or later.
func (c *Client) tlsConfigFor(addr string) *tls.Config {
	cfg := c.tlsConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

// checkReply asserts a full header and the query's transaction ID.
func checkReply(resp []byte, queryID uint16) error {
	if len(resp) < headerLength {
		return fmt.Errorf("%w: %w: %d octets", ErrDoT, ErrResponseTooShort, len(resp))
	}
	if id := binary.BigEndian.Uint16(resp); id != queryID {
		return fmt.Errorf("%w: %w: response 0x%04x, query 0x%04x", ErrDoT, ErrIDMismatch, id, queryID)
	}
	return nil
}

// NormalizeAddr returns addr with port 853 when it has none. A bare
// IPv6 address is bracketed.
func NormalizeAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, DefaultPort)
}
