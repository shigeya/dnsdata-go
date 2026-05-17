package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/shigeya/dnsdata-go/types"
)

// ErrInvalidQName is returned by [BuildQuery] when qname fails wire
// encoding (oversized labels, name too long).
var ErrInvalidQName = errors.New("dns query: invalid qname")

// DNS message header flag bits used by [BuildQuery]. Layout from
// RFC 1035 §4.1.1; the EDNS-DO bit per RFC 3225 lives in the OPT TTL
// field.
const (
	// FlagRD is the "recursion desired" header bit.
	FlagRD uint16 = 0x0100

	// optType is the IANA OPT pseudo-RR type code (RFC 6891 §6.1.2).
	optType uint16 = 41

	// udpPayloadSize is the value carried in OPT.CLASS — see
	// RFC 6891 §6.1.2. 4096 is the de-facto standard.
	udpPayloadSize uint16 = 4096

	// doBit is the DNSSEC OK flag in the OPT TTL field
	// (RFC 3225 §3 / RFC 6891 §6.1.3).
	doBit uint32 = 0x8000
)

// BuildQuery constructs a DNS query message for (qname, qtype) in
// class IN with the RD bit set and an EDNS(0) OPT pseudo-RR in the
// additional section carrying the DO bit. The same wire format works
// for DoH (RFC 8484) and plain UDP / TCP DNS (RFC 1035).
//
// Returns [ErrInvalidQName] if qname cannot be encoded.
func BuildQuery(qname string, qtype uint16) ([]byte, error) {
	return BuildQueryWithID(randomID(), qname, qtype)
}

// BuildQueryWithID is the deterministic variant of [BuildQuery] —
// tests and protocols that need to correlate a specific transaction
// ID with a response set it explicitly.
func BuildQueryWithID(id uint16, qname string, qtype uint16) ([]byte, error) {
	nameWire, err := DomainNameToWire(ensureFQDN(qname))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidQName, err)
	}

	// Header (12 bytes): id, flags, qd=1, an=0, ns=0, ar=1 (the OPT).
	buf := make([]byte, 0, 12+len(nameWire)+4+11)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, FlagRD)
	buf = binary.BigEndian.AppendUint16(buf, 1) // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0) // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0) // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 1) // ARCOUNT

	// Question: name + qtype + qclass(IN).
	buf = append(buf, nameWire...)
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, types.ClassIN)

	// EDNS(0) OPT pseudo-RR: root name + type(41) + class(payload size)
	// + ttl(DO bit) + rdlen(0).
	buf = append(buf, 0x00)
	buf = binary.BigEndian.AppendUint16(buf, optType)
	buf = binary.BigEndian.AppendUint16(buf, udpPayloadSize)
	buf = binary.BigEndian.AppendUint32(buf, doBit)
	buf = binary.BigEndian.AppendUint16(buf, 0)

	return buf, nil
}

// ensureFQDN appends a trailing dot when the caller didn't. An empty
// string encodes as the root label.
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
// failure, the function falls back to 0; resolvers tolerate duplicate
// IDs over independent queries.
func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b[:])
}

// RandomQueryID is the exported variant of [randomID], for callers
// (like resolver/auth) that want to compose [BuildQueryWithID] with
// a separately-tracked transaction ID.
func RandomQueryID() uint16 { return randomID() }
