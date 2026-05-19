package zone

import (
	"github.com/shigeya/dnsdata-go/types"
)

// RegisterHandlers wires the bundled zone RR-type handlers (TLSA,
// SMIMEA, SSHFP, …) into the package registry so
// [ResourceRecord.Handler] returns the correct typed handler.
//
// Calling this function is opt-in by design: the Go port refuses to
// produce side effects from init() per DESIGN.md §4.21. Callers that
// only need the built-in encoders (A / AAAA / NS / SOA / MX / TXT /
// SRV / CAA / CNAME / PTR / DNAME) can skip the call entirely.
//
// Consumers that want every bundled handler call this alongside
// [dnssec.RegisterHandlers]:
//
//	zone.RegisterHandlers()
//	dnssec.RegisterHandlers()
//
// This is equivalent to dnsdata-js's `registerAllHandlers()`.
//
// The function is safe to call multiple times. Each invocation
// overwrites the previous registrations atomically; this matches
// dnsdata-js's module-import semantics for `register_rr_handler`.
//
// Additional batches (SVCB / HTTPS / OPT) will be appended here as each
// P9 batch lands.
func RegisterHandlers() {
	RegisterRRHandler(types.TypeTLSA, tlsaFactory)
	RegisterRRHandler(types.TypeSMIMEA, smimeaFactory) // RFC 8162, shares TLSA wire format
	RegisterRRHandler(types.TypeSSHFP, sshfpFactory)
	RegisterRRHandler(types.TypeOPENPGPKEY, openpgpkeyFactory)
	RegisterRRHandler(types.TypeCERT, certFactory)
	RegisterRRHandler(types.TypeURI, uriFactory)
	RegisterRRHandler(types.TypeHINFO, hinfoFactory)
	RegisterRRHandler(types.TypeRP, rpFactory)
	RegisterRRHandler(types.TypeEUI48, eui48Factory)
	RegisterRRHandler(types.TypeEUI64, eui64Factory) // RFC 7043 §4, shares EUI48 wire shape
	RegisterRRHandler(types.TypeCSYNC, csyncFactory)
	RegisterRRHandler(types.TypeLOC, locFactory)
	RegisterRRHandler(types.TypeNAPTR, naptrFactory)
}
