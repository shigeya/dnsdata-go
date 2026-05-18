package doh_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shigeya/dnsdata-go/resolver/doh"
	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
)

// buildDNSResponse returns the bytes of a tiny DNS response with one
// answer record. Question section matches the answer name + type.
func buildDNSResponse(t *testing.T, name string, rrtype uint16, ttl uint32, rdata []byte) []byte {
	t.Helper()
	var b wire.Builder
	b.AppendUint16(0x1234) // ID
	b.AppendUint16(0x8180) // QR=1 RD=1 RA=1, RCODE=0
	b.AppendUint16(1)      // QDCOUNT
	b.AppendUint16(1)      // ANCOUNT
	b.AppendUint16(0)      // NSCOUNT
	b.AppendUint16(0)      // ARCOUNT
	nameWire, err := wire.DomainNameToWire(name)
	if err != nil {
		t.Fatalf("DomainNameToWire: %v", err)
	}
	b.AppendBytes(nameWire)
	b.AppendUint16(rrtype)
	b.AppendUint16(types.ClassIN)
	// Answer (re-use the same name; no compression for simplicity).
	b.AppendBytes(nameWire)
	b.AppendUint16(rrtype)
	b.AppendUint16(types.ClassIN)
	b.AppendUint32(ttl)
	b.AppendUint16(uint16(len(rdata)))
	b.AppendBytes(rdata)
	return b.Clone()
}

// buildDNSResponseWithRCODE returns a response carrying the supplied
// RCODE in the flags low nibble and no answer records.
func buildDNSResponseWithRCODE(t *testing.T, name string, rrtype uint16, rcode uint8) []byte {
	t.Helper()
	var b wire.Builder
	flags := uint16(0x8180) | uint16(rcode&0x0F)
	b.AppendUint16(0x1234)
	b.AppendUint16(flags)
	b.AppendUint16(1) // QDCOUNT
	b.AppendUint16(0) // ANCOUNT
	b.AppendUint16(0)
	b.AppendUint16(0)
	nameWire, _ := wire.DomainNameToWire(name)
	b.AppendBytes(nameWire)
	b.AppendUint16(rrtype)
	b.AppendUint16(types.ClassIN)
	return b.Clone()
}

func dnskeyRData(flags uint16, protocol, algorithm uint8, keyHex string) []byte {
	keyData, _ := hex.DecodeString(keyHex)
	rdata := make([]byte, 0, 4+len(keyData))
	rdata = binary.BigEndian.AppendUint16(rdata, flags)
	rdata = append(rdata, protocol, algorithm)
	rdata = append(rdata, keyData...)
	return rdata
}

func TestClient_Resolve_ParsesDNSKEYAnswer(t *testing.T) {
	rdata := dnskeyRData(257, 3, 13, "deadbeef")
	response := buildDNSResponse(t, "example.com.", types.TypeDNSKEY, 3600, rdata)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", doh.MediaType)
		_, _ = w.Write(response)
	}))
	t.Cleanup(srv.Close)

	c := doh.NewClient(doh.WithProviders(srv.URL))
	records, err := c.Resolve(context.Background(), "example.com.", types.TypeDNSKEY)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	rr := records[0]
	if rr.Label != "example.com." {
		t.Errorf("Label = %q", rr.Label)
	}
	if rr.Type != types.TypeDNSKEY {
		t.Errorf("Type = %d", rr.Type)
	}
	if rr.TTL != 3600 {
		t.Errorf("TTL = %d", rr.TTL)
	}
	// Value should round-trip back through the DNSKEY presentation form.
	if rr.Value != "257 3 13 3q2+7w==" {
		t.Errorf("Value = %q", rr.Value)
	}
}

// buildDNSResponseWithAuthority returns the bytes of a response that
// carries one answer + one authority record. Used to verify that the
// Authority section is surfaced by Resolve so the verifier can find
// NSEC / NSEC3 negative proofs.
func buildDNSResponseWithAuthority(t *testing.T, qname string, qtype uint16, answerOwner string, answerType uint16, answerTTL uint32, answerRData []byte, authOwner string, authType uint16, authTTL uint32, authRData []byte) []byte {
	t.Helper()
	var b wire.Builder
	b.AppendUint16(0x1234)
	b.AppendUint16(0x8180)
	b.AppendUint16(1) // QDCOUNT
	b.AppendUint16(1) // ANCOUNT
	b.AppendUint16(1) // NSCOUNT
	b.AppendUint16(0)
	qwire, err := wire.DomainNameToWire(qname)
	if err != nil {
		t.Fatalf("DomainNameToWire qname: %v", err)
	}
	b.AppendBytes(qwire)
	b.AppendUint16(qtype)
	b.AppendUint16(types.ClassIN)
	answerWire, err := wire.DomainNameToWire(answerOwner)
	if err != nil {
		t.Fatalf("DomainNameToWire answer: %v", err)
	}
	b.AppendBytes(answerWire)
	b.AppendUint16(answerType)
	b.AppendUint16(types.ClassIN)
	b.AppendUint32(answerTTL)
	b.AppendUint16(uint16(len(answerRData)))
	b.AppendBytes(answerRData)
	authWire, err := wire.DomainNameToWire(authOwner)
	if err != nil {
		t.Fatalf("DomainNameToWire auth: %v", err)
	}
	b.AppendBytes(authWire)
	b.AppendUint16(authType)
	b.AppendUint16(types.ClassIN)
	b.AppendUint32(authTTL)
	b.AppendUint16(uint16(len(authRData)))
	b.AppendBytes(authRData)
	return b.Clone()
}

func TestClient_Resolve_IncludesAuthoritySection(t *testing.T) {
	// One A record in the answer, plus one NS record in the authority.
	// Validates the fix that surfaces authority-section records so that
	// the verifier can locate NSEC / NSEC3 negative proofs.
	answerRData := []byte{192, 0, 2, 1}
	nsTargetWire, err := wire.DomainNameToWire("ns.example.com.")
	if err != nil {
		t.Fatalf("DomainNameToWire ns: %v", err)
	}
	response := buildDNSResponseWithAuthority(t,
		"www.example.com.", types.TypeA,
		"www.example.com.", types.TypeA, 60, answerRData,
		"example.com.", types.TypeNS, 3600, nsTargetWire,
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", doh.MediaType)
		_, _ = w.Write(response)
	}))
	t.Cleanup(srv.Close)

	c := doh.NewClient(doh.WithProviders(srv.URL))
	records, err := c.Resolve(context.Background(), "www.example.com.", types.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2 (answer + authority)", len(records))
	}
	if records[0].Type != types.TypeA || records[0].Label != "www.example.com." {
		t.Errorf("answer = (%q, %d), want (www.example.com., A)", records[0].Label, records[0].Type)
	}
	if records[1].Type != types.TypeNS || records[1].Label != "example.com." {
		t.Errorf("authority = (%q, %d), want (example.com., NS)", records[1].Label, records[1].Type)
	}
}

func TestClient_Resolve_PropagatesRCODE(t *testing.T) {
	response := buildDNSResponseWithRCODE(t, "missing.example.", types.TypeA, 3) // NXDOMAIN
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", doh.MediaType)
		_, _ = w.Write(response)
	}))
	t.Cleanup(srv.Close)

	c := doh.NewClient(doh.WithProviders(srv.URL))
	_, err := c.Resolve(context.Background(), "missing.example.", types.TypeA)
	if !errors.Is(err, doh.ErrResolverResponse) {
		t.Errorf("err = %v, want ErrResolverResponse", err)
	}
}

func TestClient_Resolve_RejectsMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", doh.MediaType)
		_, _ = w.Write([]byte{0x00, 0x01, 0x02}) // way too short
	}))
	t.Cleanup(srv.Close)

	c := doh.NewClient(doh.WithProviders(srv.URL))
	_, err := c.Resolve(context.Background(), "example.com.", types.TypeA)
	if !errors.Is(err, doh.ErrResolverResponse) {
		t.Errorf("err = %v, want ErrResolverResponse", err)
	}
}
