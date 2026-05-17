package dnssec

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// NSEC3 is the RR handler for NSEC3 records (RFC 5155 §3).
type NSEC3 struct {
	rr *zone.ResourceRecord

	HashAlgorithm   uint8
	Flags           uint8
	Iterations      uint16
	Salt            []byte
	NextHashedOwner []byte
	TypeBitmap      []byte
	CoveredTypes    []uint16
}

// ParseNSEC3 constructs an NSEC3 from RR presentation form:
// `<hash_algo> <flags> <iterations> <salt|-> <next_hashed_owner_b32hex> [<type>...]`.
func ParseNSEC3(rr *zone.ResourceRecord, value string) (*NSEC3, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) < 5 {
		return nil, fmt.Errorf("%w: NSEC3: %q", ErrPresentationFormat, value)
	}

	hashAlgo, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3 hash-algo %q: %v", ErrPresentationFormat, parts[0], err)
	}
	flags, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3 flags %q: %v", ErrPresentationFormat, parts[1], err)
	}
	iters, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3 iterations %q: %v", ErrPresentationFormat, parts[2], err)
	}

	var salt []byte
	if parts[3] != "-" {
		salt, err = hex.DecodeString(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: NSEC3 salt: %v", ErrPresentationFormat, err)
		}
	}

	nextHashed, err := base32HexDecode(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3 next-hashed-owner: %v", ErrPresentationFormat, err)
	}

	covered := make([]uint16, 0, len(parts)-5)
	for _, p := range parts[5:] {
		if t, err := types.StringToRRType(p); err == nil {
			covered = append(covered, t)
		}
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i] < covered[j] })

	return &NSEC3{
		rr:              rr,
		HashAlgorithm:   uint8(hashAlgo),
		Flags:           uint8(flags),
		Iterations:      uint16(iters),
		Salt:            salt,
		NextHashedOwner: nextHashed,
		TypeBitmap:      EncodeTypeBitmap(covered),
		CoveredTypes:    covered,
	}, nil
}

// CoversType reports whether the bitmap covers t.
func (n *NSEC3) CoversType(t uint16) bool {
	for _, x := range n.CoveredTypes {
		if x == t {
			return true
		}
		if x > t {
			return false
		}
	}
	return false
}

// nsec3OptOutFlag is bit 0 of the NSEC3 Flags field (RFC 5155 §3.1.2.1).
const nsec3OptOutFlag uint8 = 0x01

// HasOptOut reports whether the NSEC3 opt-out flag is set
// (RFC 5155 §6 — when set, the NSEC3 may safely omit insecure
// delegations from its [owner, next) range).
func (n *NSEC3) HasOptOut() bool {
	if n == nil {
		return false
	}
	return n.Flags&nsec3OptOutFlag != 0
}

// OwnerHashFromName decodes the leftmost label of an NSEC3 owner name
// as base32hex (RFC 5155 §1.3). For owner "ABCD0123.example.com." this
// returns the raw hash bytes encoded in "ABCD0123".
func OwnerHashFromName(owner string) ([]byte, error) {
	cleaned := strings.TrimSuffix(owner, ".")
	if cleaned == "" {
		return nil, fmt.Errorf("%w: NSEC3 owner is empty", ErrPresentationFormat)
	}
	label, _, _ := strings.Cut(cleaned, ".")
	if label == "" {
		return nil, fmt.Errorf("%w: NSEC3 owner has no leftmost label: %q", ErrPresentationFormat, owner)
	}
	return base32HexDecode(label)
}

// CoversHash reports whether target falls strictly between ownerHash
// and n.NextHashedOwner in NSEC3 sort order (RFC 5155 §6.1: byte-wise
// numeric order on the hash output).
//
// Equal to either endpoint returns false: matching denial is a
// separate concept from covering denial.
//
// The wrap case where NextHashedOwner <= ownerHash is treated as the
// zone-trailing NSEC3 and handled symmetrically with [NSEC.CoversName].
func (n *NSEC3) CoversHash(ownerHash, target []byte) bool {
	if n == nil {
		return false
	}
	cmpOwner := bytes.Compare(target, ownerHash)
	cmpNext := bytes.Compare(target, n.NextHashedOwner)
	if cmpOwner == 0 || cmpNext == 0 {
		return false
	}
	if bytes.Compare(n.NextHashedOwner, ownerHash) <= 0 {
		return cmpOwner > 0 || cmpNext < 0
	}
	return cmpOwner > 0 && cmpNext < 0
}

// ProvesNoData mirrors [NSEC.ProvesNoData] for NSEC3: the bitmap must
// NOT cover qtype, and must NOT cover CNAME.
func (n *NSEC3) ProvesNoData(qtype uint16) bool {
	if n == nil {
		return false
	}
	if qtype == types.TypeCNAME {
		return !n.CoversType(types.TypeCNAME)
	}
	return !n.CoversType(qtype) && !n.CoversType(types.TypeCNAME)
}

// ProvesNoDS reports whether n's type bitmap has the shape of a signed
// no-DS delegation (NS present, DS absent, SOA absent). Like its NSEC
// counterpart, this is bitmap-only — the caller must additionally
// confirm n is a matching or covering NSEC3 for the child name.
func (n *NSEC3) ProvesNoDS() bool {
	if n == nil {
		return false
	}
	hasNS := false
	hasDS := false
	hasSOA := false
	for _, t := range n.CoveredTypes {
		switch t {
		case types.TypeNS:
			hasNS = true
		case types.TypeDS:
			hasDS = true
		case types.TypeSOA:
			hasSOA = true
		}
	}
	return hasNS && !hasDS && !hasSOA
}


// ComputeNSEC3Hash hashes name per RFC 5155 §5 with the given salt and
// iteration count.
//
// Only algorithm 1 (SHA-1) is defined by IANA; other values return
// [ErrUnsupportedAlgorithm].
func ComputeNSEC3Hash(name string, algorithm uint8, iterations uint16, salt []byte) ([]byte, error) {
	if algorithm != 1 {
		return nil, fmt.Errorf("%w: NSEC3 hash algorithm %d", ErrUnsupportedAlgorithm, algorithm)
	}
	nameWire, err := wire.DomainNameToWire(strings.ToLower(name))
	if err != nil {
		return nil, err
	}

	h := sha1.New()
	h.Write(nameWire)
	h.Write(salt)
	digest := h.Sum(nil)

	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}
	return digest, nil
}

// WireBody emits the NSEC3 RDATA per RFC 5155 §3.2.
func (n *NSEC3) WireBody(b *wire.Builder) error {
	rdlen := 6 + len(n.Salt) + len(n.NextHashedOwner) + len(n.TypeBitmap)
	b.AppendUint16(uint16(rdlen))
	b.AppendUint8(n.HashAlgorithm)
	b.AppendUint8(n.Flags)
	b.AppendUint16(n.Iterations)
	b.AppendUint8(uint8(len(n.Salt)))
	b.AppendBytes(n.Salt)
	b.AppendUint8(uint8(len(n.NextHashedOwner)))
	b.AppendBytes(n.NextHashedOwner)
	b.AppendBytes(n.TypeBitmap)
	return nil
}

// Clone returns a deep copy of n.
func (n *NSEC3) Clone() zone.RecordHandler {
	return &NSEC3{
		rr:              n.rr,
		HashAlgorithm:   n.HashAlgorithm,
		Flags:           n.Flags,
		Iterations:      n.Iterations,
		Salt:            append([]byte(nil), n.Salt...),
		NextHashedOwner: append([]byte(nil), n.NextHashedOwner...),
		TypeBitmap:      append([]byte(nil), n.TypeBitmap...),
		CoveredTypes:    append([]uint16(nil), n.CoveredTypes...),
	}
}

// NSEC3Param is the RR handler for NSEC3PARAM records (RFC 5155 §4).
//
// Wire shape mirrors the first four fields of NSEC3 (no Next Hashed
// Owner Name, no Type Bit Maps).
type NSEC3Param struct {
	rr *zone.ResourceRecord

	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	Salt          []byte
}

// ParseNSEC3Param constructs an NSEC3PARAM from presentation form:
// `<hash_algo> <flags> <iterations> <salt|->`.
func ParseNSEC3Param(rr *zone.ResourceRecord, value string) (*NSEC3Param, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) < 4 {
		return nil, fmt.Errorf("%w: NSEC3PARAM: %q", ErrPresentationFormat, value)
	}
	hashAlgo, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3PARAM hash-algo %q: %v", ErrPresentationFormat, parts[0], err)
	}
	flags, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3PARAM flags %q: %v", ErrPresentationFormat, parts[1], err)
	}
	iters, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: NSEC3PARAM iterations %q: %v", ErrPresentationFormat, parts[2], err)
	}
	var salt []byte
	if parts[3] != "-" {
		salt, err = hex.DecodeString(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: NSEC3PARAM salt: %v", ErrPresentationFormat, err)
		}
	}
	return &NSEC3Param{
		rr:            rr,
		HashAlgorithm: uint8(hashAlgo),
		Flags:         uint8(flags),
		Iterations:    uint16(iters),
		Salt:          salt,
	}, nil
}

// WireBody emits the NSEC3PARAM RDATA per RFC 5155 §4.2.
func (p *NSEC3Param) WireBody(b *wire.Builder) error {
	rdlen := 5 + len(p.Salt)
	b.AppendUint16(uint16(rdlen))
	b.AppendUint8(p.HashAlgorithm)
	b.AppendUint8(p.Flags)
	b.AppendUint16(p.Iterations)
	b.AppendUint8(uint8(len(p.Salt)))
	b.AppendBytes(p.Salt)
	return nil
}

// Clone returns a deep copy of p.
func (p *NSEC3Param) Clone() zone.RecordHandler {
	return &NSEC3Param{
		rr:            p.rr,
		HashAlgorithm: p.HashAlgorithm,
		Flags:         p.Flags,
		Iterations:    p.Iterations,
		Salt:          append([]byte(nil), p.Salt...),
	}
}

// base32HexDecode decodes the base32hex (RFC 4648 §7) form used by
// NSEC3 next-hashed-owner labels. Trailing `=` padding is stripped.
func base32HexDecode(input string) ([]byte, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	cleaned := strings.ToUpper(strings.TrimRight(input, "="))
	var bits []uint8
	for _, c := range cleaned {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base32hex character %q", c)
		}
		for i := 4; i >= 0; i-- {
			bits = append(bits, uint8(idx>>i)&1)
		}
	}
	out := make([]byte, len(bits)/8)
	for i := range out {
		var b uint8
		for bit := 0; bit < 8; bit++ {
			b = b<<1 | bits[i*8+bit]
		}
		out[i] = b
	}
	return out, nil
}
