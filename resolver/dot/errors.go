package dot

import "errors"

// Sentinel errors. Callers classify failures with [errors.Is].
var (
	// ErrDoT wraps every transport failure of this package: dial, TLS
	// handshake or authentication, framing, and a reply that is not
	// one to the query.
	ErrDoT = errors.New("dot resolver error")

	// ErrNoServers is returned when no server is configured.
	ErrNoServers = errors.New("dot: no servers configured")

	// ErrAllServersFailed is returned when every server failed; the
	// first failure is joined to it.
	ErrAllServersFailed = errors.New("dot: all servers failed")

	// ErrResponseTooShort reports a reply shorter than a DNS header.
	ErrResponseTooShort = errors.New("dot: response too short")

	// ErrIDMismatch reports a reply whose transaction ID is not the
	// query's.
	ErrIDMismatch = errors.New("dot: response transaction ID mismatch")

	// ErrResolverResponse reports a response [Client.Resolve] cannot
	// parse. A non-zero RCODE is not an error.
	ErrResolverResponse = errors.New("dot: bad response")
)
