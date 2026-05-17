package doh

import "errors"

// Sentinel errors. Callers can classify failures with [errors.Is].
var (
	// ErrDoH is the umbrella error wrapping every transport failure
	// from this package.
	ErrDoH = errors.New("doh error")

	// ErrNoProviders is returned when [Client.Query] is asked to run
	// against an empty provider list.
	ErrNoProviders = errors.New("doh: no providers configured")

	// ErrAllProvidersFailed is returned when every configured provider
	// errored or returned a non-2xx response. The underlying error
	// from the first provider is wrapped so [errors.Is] / [errors.As]
	// against more specific errors continues to work.
	ErrAllProvidersFailed = errors.New("doh: all providers failed")

	// ErrUnexpectedStatus is returned when a provider answered with a
	// non-2xx HTTP status code.
	ErrUnexpectedStatus = errors.New("doh: unexpected http status")

	// ErrUnexpectedContentType is returned when a provider answered
	// with a Content-Type other than `application/dns-message`.
	ErrUnexpectedContentType = errors.New("doh: unexpected content type")

	// ErrInvalidQName indicates the caller-supplied query name failed
	// wire encoding (oversized labels, etc.).
	ErrInvalidQName = errors.New("doh: invalid qname")
)
