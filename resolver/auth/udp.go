package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// queryUDP sends query over UDP to one server, retransmitting it up to
// c.udpAttempts times, and returns the first reply that carries
// queryID. Every attempt reuses the same socket, so a late reply to an
// earlier transmission is accepted while a later attempt is waiting.
// Datagrams that are too short or carry another ID are skipped. Returns
// [ErrUDPTruncated] when the reply has the TC flag set so the caller
// can retry on TCP.
func (c *Client) queryUDP(ctx context.Context, addr string, queryID uint16, query []byte) ([]byte, error) {
	conn, err := c.dial.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: udp dial %s: %v", ErrAuth, addr, err)
	}
	defer conn.Close()
	// Closing the socket on cancellation unblocks a pending read; the
	// read error is then classified by contextDone.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	buf := make([]byte, c.udpBufSize)
	stray := strayDatagrams{}
	var lastErr error
	for attempt := 1; attempt <= c.udpAttempts; attempt++ {
		if err := contextDone(ctx); err != nil {
			return nil, fmt.Errorf("%w: udp %s: %w", ErrAuth, addr, err)
		}
		resp, err := c.udpAttempt(ctx, conn, buf, queryID, query, stray)
		if err == nil {
			if isTruncated(resp) {
				return nil, ErrUDPTruncated
			}
			return resp, nil
		}
		if ctxErr := contextDone(ctx); ctxErr != nil {
			return nil, fmt.Errorf("%w: udp %s: %w", ErrAuth, addr, ctxErr)
		}
		if !isTimeout(err) {
			return nil, fmt.Errorf("%w: udp %s: %v", ErrAuth, addr, err)
		}
		lastErr = err
	}
	exhausted := fmt.Errorf("%w: udp %s: no reply after %d attempts: %v", ErrAuth, addr, c.udpAttempts, lastErr)
	return nil, errors.Join(append([]error{exhausted}, stray.errors()...)...)
}

// strayDatagrams keeps the last rejection of each kind ([ErrIDMismatch],
// [ErrResponseTooShort]) seen while waiting, so the final error names
// every kind that arrived.
type strayDatagrams map[error]error

// strayKinds are the rejections [validateResponse] returns, in the
// order the final error lists them.
var strayKinds = []error{ErrIDMismatch, ErrResponseTooShort}

// record files err under the sentinel it wraps.
func (s strayDatagrams) record(err error) {
	for _, kind := range strayKinds {
		if errors.Is(err, kind) {
			s[kind] = err
			return
		}
	}
}

// errors returns the recorded rejections in a stable order.
func (s strayDatagrams) errors() []error {
	out := make([]error, 0, len(s))
	for _, kind := range strayKinds {
		if err, ok := s[kind]; ok {
			out = append(out, err)
		}
	}
	return out
}

// udpAttempt transmits query once and reads until a reply carrying
// queryID arrives or the attempt's deadline passes. Datagrams rejected
// by [validateResponse] are recorded in stray and skipped.
func (c *Client) udpAttempt(ctx context.Context, conn net.Conn, buf []byte, queryID uint16, query []byte, stray strayDatagrams) ([]byte, error) {
	if err := conn.SetDeadline(c.attemptDeadline(ctx)); err != nil {
		return nil, fmt.Errorf("deadline: %w", err)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
		if verr := validateResponse(buf[:n], queryID); verr != nil {
			stray.record(verr)
			continue
		}
		return buf[:n], nil
	}
}

// attemptDeadline is the end of one transport attempt: now plus the
// per-attempt timeout, or the context's deadline if that is sooner.
func (c *Client) attemptDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		return d
	}
	return deadline
}

// contextDone reports why ctx is finished, or nil. A deadline that has
// passed counts even before the context's own timer fires, so a read
// that timed out at the context's deadline is not retransmitted.
func contextDone(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return nil
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isTruncated reports whether the TC flag of the DNS header is set.
func isTruncated(resp []byte) bool {
	return len(resp) >= 4 && resp[2]&0x02 != 0
}
