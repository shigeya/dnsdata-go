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
