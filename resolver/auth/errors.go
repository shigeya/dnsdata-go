package auth

import "errors"

// Sentinel errors. Callers can classify failures with [errors.Is].
var (
	// ErrAuth is the umbrella error wrapping every transport failure
	// from this package.
	ErrAuth = errors.New("auth resolver error")

	// ErrNoServers is returned by [Client.Query] when the configured
	// server list is empty.
	ErrNoServers = errors.New("auth: no servers configured")

	// ErrAllServersFailed is returned when every configured server
	// errored. The first inner error is joined via [errors.Join] so
	// callers can still discriminate via the underlying sentinel.
	ErrAllServersFailed = errors.New("auth: all servers failed")

	// ErrUDPTruncated is returned in response paths to indicate the
	// server set the TC flag and the client must retry on TCP. The
	// outer Query call handles the retry transparently; the error is
	// exposed for users who call the lower-level helpers.
	ErrUDPTruncated = errors.New("auth: udp response truncated, retry on tcp")

	// ErrResponseTooShort is returned when the server sent fewer than
	// the 12-byte DNS header.
	ErrResponseTooShort = errors.New("auth: response too short")

	// ErrIDMismatch is returned when the response's transaction ID
	// doesn't match the query's. Mitigates Kaminsky-style off-path
	// poisoning attempts within a single query / response pairing.
	ErrIDMismatch = errors.New("auth: response transaction ID mismatch")
)
