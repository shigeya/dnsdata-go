package auth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/shigeya/dnsdata-go/resolver/internal/stream"
	"github.com/shigeya/dnsdata-go/wire"
)

// DefaultUDPBufferSize is the maximum UDP response size the client
// is willing to accept. Matches the EDNS payload size advertised by
// [wire.BuildQuery] (4096 octets).
const DefaultUDPBufferSize = 4096

// DefaultTimeout is how long one transport attempt waits: one UDP
// transmission and its reply, or one TCP exchange (dial, query and
// reply). The total Query budget is the caller's context deadline.
const DefaultTimeout = 2 * time.Second

// DefaultUDPAttempts is how many times a query is sent over UDP to one
// server before the client moves to the next server.
const DefaultUDPAttempts = 3

// Client speaks plain DNS over UDP / TCP. The zero value is not
// usable; build with [NewClient].
//
// Concurrency: every field is set once at construction and treated as
// read-only thereafter. Concurrent calls to [Client.Query] /
// [Client.Resolve] are safe.
type Client struct {
	servers     []string
	timeout     time.Duration
	udpAttempts int
	udpBufSize  int
	dial        dialer // injectable for tests
	queryOpts   wire.QueryOptions
}

// dialer abstracts net.Dialer so tests can swap in fake network
// transports. The real implementation is the package-local
// [defaultDialer] which delegates to net.Dialer.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type netDialer struct{ d net.Dialer }

func (n netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.d.DialContext(ctx, network, address)
}

// Option configures a [Client] at construction time.
type Option func(*Client)

// WithServers sets the list of server addresses to try in order. Each
// entry is an `ip:port` string (e.g. "1.1.1.1:53"). The empty form
// uses the default port 53 — see [NormalizeAddr] for the rule.
func WithServers(addrs ...string) Option {
	return func(c *Client) {
		c.servers = make([]string, 0, len(addrs))
		for _, a := range addrs {
			c.servers = append(c.servers, NormalizeAddr(a))
		}
	}
}

// WithTimeout sets how long one transport attempt waits (default
// [DefaultTimeout], 2s): one UDP transmission and its reply, or one TCP
// exchange. A server is given up after [WithUDPAttempts] UDP attempts,
// so without a context deadline one server can take attempts × timeout
// (plus one TCP attempt when the UDP reply is truncated). The caller's
// context deadline bounds the whole query and cuts any attempt short.
//
// Until v0.12.0 this was the single UDP wait per server (default 5s);
// a caller that passed its whole budget here should pass it as the
// context deadline instead.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithUDPAttempts sets how many times a query is sent over UDP to one
// server before moving to the next (default [DefaultUDPAttempts], 3).
// Each attempt waits [WithTimeout]. Retransmissions reuse the socket and
// the transaction ID, so a late reply to an earlier transmission is
// accepted. Values below 1 are raised to 1 (no retransmission).
func WithUDPAttempts(n int) Option {
	return func(c *Client) {
		if n < 1 {
			n = 1
		}
		c.udpAttempts = n
	}
}

// WithUDPBufferSize overrides the UDP receive buffer. The OPT record
// in [wire.BuildQuery] advertises 4096 — values below 512 are
// clamped up to RFC 1035's minimum DNS UDP message size.
func WithUDPBufferSize(n int) Option {
	return func(c *Client) {
		if n < 512 {
			n = 512
		}
		c.udpBufSize = n
	}
}

// WithCheckingDisabled sets the CD bit on every query (RFC 4035
// §3.2.2), so a validating server returns data it would reject as
// bogus instead of SERVFAIL and the caller can validate it itself.
// Off by default.
func WithCheckingDisabled(cd bool) Option {
	return func(c *Client) { c.queryOpts.CheckingDisabled = cd }
}

// WithDialer is an internal option to inject a custom dialer.
// Exported for tests only via the test-helper convention; production
// callers should not touch it.
func WithDialer(d net.Dialer) Option {
	return func(c *Client) { c.dial = netDialer{d: d} }
}

// NewClient constructs a Client with the supplied options. A server
// list is REQUIRED; calling Query / Resolve on an unconfigured client
// returns [ErrNoServers].
func NewClient(opts ...Option) *Client {
	c := &Client{
		timeout:     DefaultTimeout,
		udpAttempts: DefaultUDPAttempts,
		udpBufSize:  DefaultUDPBufferSize,
		dial:        netDialer{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Servers returns a fresh copy of the configured server list.
func (c *Client) Servers() []string {
	return append([]string(nil), c.servers...)
}

// Query issues a DNS query for (qname, qtype) and returns the raw
// response message bytes from the first server that succeeds. The
// caller is responsible for parsing the response (see
// [wire.ParseMessage]).
func (c *Client) Query(ctx context.Context, qname string, qtype uint16) ([]byte, error) {
	queryID := wire.RandomQueryID()
	msg, err := wire.BuildQueryWithOptions(queryID, qname, qtype, c.queryOpts)
	if err != nil {
		return nil, err
	}
	return c.QueryRaw(ctx, queryID, msg)
}

// QueryRaw sends a prebuilt DNS query message and returns the
// response bytes. The caller supplies the transaction ID separately
// so the client can verify the response is a reply to this query
// (mitigates simple ID-spoofing within the wire transport).
func (c *Client) QueryRaw(ctx context.Context, queryID uint16, query []byte) ([]byte, error) {
	if len(c.servers) == 0 {
		return nil, ErrNoServers
	}
	var firstErr error
	for _, addr := range c.servers {
		if err := contextDone(ctx); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: %w", ErrAuth, err)
			}
			break
		}
		resp, err := c.queryOne(ctx, addr, queryID, query)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return resp, nil
	}
	if firstErr == nil {
		return nil, ErrAllServersFailed
	}
	return nil, errors.Join(ErrAllServersFailed, firstErr)
}

// queryOne attempts the (UDP → TCP-on-truncation) sequence against a
// single server. Errors wrap [ErrAuth], and the context's error when
// the context ended during the attempt.
func (c *Client) queryOne(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	resp, err := c.queryUDP(ctx, addr, queryID, query)
	if errors.Is(err, ErrUDPTruncated) {
		resp, err = c.queryTCP(ctx, addr, queryID, query)
	}
	if err == nil {
		return resp, nil
	}
	return nil, withContextError(ctx, err)
}

// withContextError joins the context's error to err when the context
// is done and err does not already wrap it (dial and TCP failures are
// reported as plain network errors).
func withContextError(ctx context.Context, err error) error {
	ctxErr := contextDone(ctx)
	if ctxErr == nil || errors.Is(err, ctxErr) {
		return err
	}
	return errors.Join(err, ctxErr)
}

// queryTCP sends query over TCP using the RFC 1035 §4.2.2 length-
// prefixed framing ([stream.Exchange], shared with resolver/dot). One
// attempt: TCP retransmits on its own.
func (c *Client) queryTCP(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	deadline := c.attemptDeadline(ctx)

	conn, err := c.dial.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: tcp dial %s: %v", ErrAuth, addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: tcp deadline: %v", ErrAuth, err)
	}

	resp, err := stream.Exchange(conn, query)
	if err != nil {
		return nil, fmt.Errorf("%w: tcp %s: %v", ErrAuth, addr, err)
	}
	if err := validateResponse(resp, queryID); err != nil {
		return nil, err
	}
	return resp, nil
}

// validateResponse asserts the response has at least a DNS header
// and the transaction ID matches the query.
func validateResponse(resp []byte, queryID uint16) error {
	if len(resp) < 12 {
		return fmt.Errorf("%w: %d bytes", ErrResponseTooShort, len(resp))
	}
	respID := binary.BigEndian.Uint16(resp[0:2])
	if respID != queryID {
		return fmt.Errorf("%w: response ID 0x%04x, query 0x%04x", ErrIDMismatch, respID, queryID)
	}
	return nil
}

// NormalizeAddr ensures addr has a port suffix, defaulting to 53.
// IPv6 literals must already include brackets when supplied as
// `[::1]:53`; bare IPv6 without brackets is ambiguous and treated as
// "ip:port form needed" by the caller.
func NormalizeAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
