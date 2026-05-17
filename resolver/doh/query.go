package doh

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// DNS message header flags. Bit layout from RFC 1035 §4.1.1, with the
// DO bit defined in RFC 3225 (EDNS) carried in the OPT TTL field.
const (
	// flagRD = recursion desired
	flagRD uint16 = 0x0100

	// EDNS0 OPT type code (41) per RFC 6891 §6.1.2.
	optType uint16 = 41

	// udpPayloadSize is the value we advertise in OPT.CLASS. Even
	// though DoH never deals in UDP packets, 4096 is the canonical
	// "we can handle big responses" hint and most resolvers expect it.
	udpPayloadSize uint16 = 4096

	// doBit is the high-order flag of the OPT TTL field (RFC 3225 §3),
	// asking the resolver to return DNSSEC RRSIGs.
	doBit uint32 = 0x8000
)

// BuildQuery constructs an RFC 8484 query message for (qname, qtype)
// in class IN. The message includes an EDNS(0) OPT record with the DO
// bit set so the responding resolver returns DNSSEC signatures.
//
// Returns [ErrInvalidQName] if the qname cannot be encoded.
func BuildQuery(qname string, qtype uint16) ([]byte, error) {
	return buildQueryWithID(randomID(), qname, qtype)
}

// buildQueryWithID is the deterministic variant of [BuildQuery] used
// by the tests; production callers should not need it.
func buildQueryWithID(id uint16, qname string, qtype uint16) ([]byte, error) {
	nameWire, err := wire.DomainNameToWire(ensureFQDN(qname))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidQName, err)
	}

	// Header (12 bytes): id, flags, qd=1, an=0, ns=0, ar=1 (the OPT).
	buf := make([]byte, 0, 12+len(nameWire)+4+11)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, flagRD)
	buf = binary.BigEndian.AppendUint16(buf, 1) // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0) // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0) // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 1) // ARCOUNT

	// Question: name + qtype + qclass(IN).
	buf = append(buf, nameWire...)
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, types.ClassIN)

	// EDNS(0) OPT pseudo-RR in the additional section:
	//   NAME(1 = root) + TYPE(2) + CLASS(2 = UDP payload size) +
	//   TTL(4, with DO bit) + RDLEN(2 = 0).
	buf = append(buf, 0x00) // root name
	buf = binary.BigEndian.AppendUint16(buf, optType)
	buf = binary.BigEndian.AppendUint16(buf, udpPayloadSize)
	buf = binary.BigEndian.AppendUint32(buf, doBit)
	buf = binary.BigEndian.AppendUint16(buf, 0) // RDLEN

	return buf, nil
}

// ensureFQDN appends a trailing dot when the caller didn't, so the
// wire encoder reads the name as absolute. An empty string is allowed
// and encodes as the root label.
func ensureFQDN(name string) string {
	if name == "" {
		return "."
	}
	if name[len(name)-1] == '.' {
		return name
	}
	return name + "."
}

// randomID draws a cryptographically random uint16 for use as the DNS
// transaction ID. On the (vanishingly unlikely) event of a read
// failure, the function falls back to 0; recursive resolvers tolerate
// duplicate IDs over different queries.
func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b[:])
}
