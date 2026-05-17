package auth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/shigeya/dnsdata-go/wire"
)

// DefaultUDPBufferSize is the maximum UDP response size the client
// is willing to accept. Matches the EDNS payload size advertised by
// [wire.BuildQuery] (4096 octets).
const DefaultUDPBufferSize = 4096

// DefaultTimeout caps a single transport attempt (UDP read or TCP
// dial+read). The total Query budget is governed by the caller's
// context.Deadline; this is the inner per-server timeout.
const DefaultTimeout = 5 * time.Second

// Client speaks plain DNS over UDP / TCP. The zero value is not
// usable; build with [NewClient].
//
// Concurrency: every field is set once at construction and treated as
// read-only thereafter. Concurrent calls to [Client.Query] /
// [Client.Resolve] are safe.
type Client struct {
	servers    []string
	timeout    time.Duration
	udpBufSize int
	dial       dialer // injectable for tests
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

// WithTimeout overrides the per-server per-transport timeout
// (default 5s). The total query budget remains the caller's context.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
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
		timeout:    DefaultTimeout,
		udpBufSize: DefaultUDPBufferSize,
		dial:       netDialer{},
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
	msg, err := wire.BuildQueryWithID(queryID, qname, qtype)
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
// single server. Errors wrap [ErrAuth].
func (c *Client) queryOne(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	resp, err := c.queryUDP(ctx, addr, queryID, query)
	if err == nil {
		return resp, nil
	}
	if errors.Is(err, ErrUDPTruncated) {
		return c.queryTCP(ctx, addr, queryID, query)
	}
	return nil, err
}

// queryUDP sends query over UDP and reads exactly one datagram back.
// Returns [ErrUDPTruncated] when the response's TC flag is set so the
// caller can retry on TCP.
func (c *Client) queryUDP(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	conn, err := c.dial.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: udp dial %s: %v", ErrAuth, addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: udp deadline: %v", ErrAuth, err)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("%w: udp write %s: %v", ErrAuth, addr, err)
	}

	buf := make([]byte, c.udpBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: udp read %s: %v", ErrAuth, addr, err)
	}
	resp := buf[:n]
	if err := validateResponse(resp, queryID); err != nil {
		return nil, err
	}
	// Check the TC (truncation) bit in the flags word.
	if len(resp) >= 4 && resp[2]&0x02 != 0 {
		return nil, ErrUDPTruncated
	}
	return resp, nil
}

// queryTCP sends query over TCP using the RFC 1035 §4.2.2 length-
// prefixed framing.
func (c *Client) queryTCP(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	conn, err := c.dial.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: tcp dial %s: %v", ErrAuth, addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: tcp deadline: %v", ErrAuth, err)
	}

	// Length prefix + query.
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(query)))
	if _, err := conn.Write(prefix); err != nil {
		return nil, fmt.Errorf("%w: tcp write prefix: %v", ErrAuth, err)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("%w: tcp write query: %v", ErrAuth, err)
	}

	// Read length-prefixed response.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("%w: tcp read prefix: %v", ErrAuth, err)
	}
	respLen := binary.BigEndian.Uint16(hdr)
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("%w: tcp read body: %v", ErrAuth, err)
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
