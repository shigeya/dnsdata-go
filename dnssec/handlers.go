package dnssec

import (
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// RegisterHandlers wires the DNSSEC RR-type handlers (DNSKEY, CDNSKEY,
// RRSIG, DS, CDS, NSEC, NSEC3, NSEC3PARAM) into the zone-package
// registry so [zone.ResourceRecord.Handler] returns the correct typed
// handler for DNSSEC records.
//
// Calling this function is opt-in by design: the Go port refuses to
// produce side effects from init() per DESIGN.md §4.21. Callers that
// only need to parse DNSSEC records into [zone.ResourceRecord.Value]
// (text) can skip the call.
//
// The function is safe to call multiple times. Each invocation
// overwrites the previous registrations atomically; this matches
// dnsdata-js's module-import semantics for `register_rr_handler`.
//
// In dnsdata-js this happens automatically when `dnssec_rr.ts` is
// loaded:
//
//	register_rr_handler(StringToRRType('DNSKEY'), ...)
//	register_rr_handler(StringToRRType('RRSIG'),  ...)
//	register_rr_handler(StringToRRType('DS'),     ...)
//	...
func RegisterHandlers() {
	zone.RegisterRRHandler(types.TypeDNSKEY, dnsKeyFactory)
	zone.RegisterRRHandler(types.TypeCDNSKEY, dnsKeyFactory) // RFC 7344 §3.2
	zone.RegisterRRHandler(types.TypeRRSIG, rrsigFactory)
	zone.RegisterRRHandler(types.TypeDS, dsFactory)
	zone.RegisterRRHandler(types.TypeCDS, dsFactory) // RFC 7344 §3.1
	zone.RegisterRRHandler(types.TypeNSEC, nsecFactory)
	zone.RegisterRRHandler(types.TypeNSEC3, nsec3Factory)
	zone.RegisterRRHandler(types.TypeNSEC3PARAM, nsec3ParamFactory)
}

// dnsKeyFactory adapts [ParseDNSKey] into the [zone.HandlerFactory]
// signature. On parse failure it returns nil so the zone parser falls
// back to keeping the value as text (TS parity).
func dnsKeyFactory(rr *zone.ResourceRecord, value string) zone.RecordHandler {
	h, err := ParseDNSKey(rr, value)
	if err != nil {
		return nil
	}
	return h
}

func rrsigFactory(rr *zone.ResourceRecord, value string) zone.RecordHandler {
	h, err := ParseRRSig(rr, value)
	if err != nil {
		return nil
	}
	return h
}

func dsFactory(rr *zone.ResourceRecord, value string) zone.RecordHandler {
	h, err := ParseDS(rr, value)
	if err != nil {
		return nil
	}
	return h
}

func nsecFactory(rr *zone.ResourceRecord, value string) zone.RecordHandler {
	h, err := ParseNSEC(rr, value)
	if err != nil {
		return nil
	}
	return h
}

func nsec3Factory(rr *zone.ResourceRecord, value string) zone.RecordHandler {
	h, err := ParseNSEC3(rr, value)
	if err != nil {
		return nil
	}
	return h
}

func nsec3ParamFactory(rr *zone.ResourceRecord, value string) zone.RecordHandler {
	h, err := ParseNSEC3Param(rr, value)
	if err != nil {
		return nil
	}
	return h
}
