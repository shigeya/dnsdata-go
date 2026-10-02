package zone_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// noEncoderType has neither a built-in encoder nor a registered handler.
const noEncoderType = uint16(65400)

func wireBody(t *testing.T, rr *zone.ResourceRecord) []byte {
	t.Helper()
	var b wire.Builder
	if err := rr.WireBody(&b); err != nil {
		t.Fatalf("WireBody: %v", err)
	}
	return b.Clone()
}

func TestNewResourceRecordWithRData_FallsBackToReceivedOctets(t *testing.T) {
	rdata := []byte{0xde, 0xad, 0xbe, 0xef}
	rr, err := zone.NewResourceRecordWithRData("x.test.", 60, types.ClassIN, noEncoderType, "a presentation form", rdata)
	if err != nil {
		t.Fatal(err)
	}
	rdata[0] = 0 // the record keeps its own copy
	if got, want := wireBody(t, rr), []byte{0, 4, 0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(got, want) {
		t.Errorf("WireBody = %x, want %x", got, want)
	}
	if rr.Value != "a presentation form" {
		t.Errorf("Value = %q, want the presentation form", rr.Value)
	}
}

func TestNewResourceRecordWithRData_EmptyRData(t *testing.T) {
	rr, err := zone.NewResourceRecordWithRData("x.test.", 60, types.ClassIN, noEncoderType, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := wireBody(t, rr); !bytes.Equal(got, []byte{0, 0}) {
		t.Errorf("WireBody = %x, want an empty RDATA", got)
	}
}

// An encoder, when there is one, still writes the RDATA: the received
// octets are only a fallback.
func TestNewResourceRecordWithRData_EncoderWins(t *testing.T) {
	rr, err := zone.NewResourceRecordWithRData("x.test.", 60, types.ClassIN, types.TypeA, "192.0.2.1", []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := wireBody(t, rr), []byte{0, 4, 192, 0, 2, 1}; !bytes.Equal(got, want) {
		t.Errorf("WireBody = %x, want %x", got, want)
	}
}

func TestNewResourceRecordWithRData_TooLong(t *testing.T) {
	_, err := zone.NewResourceRecordWithRData("x.test.", 60, types.ClassIN, noEncoderType, "", make([]byte, 0x10000))
	if !errors.Is(err, zone.ErrRDataFormat) {
		t.Fatalf("err = %v, want ErrRDataFormat", err)
	}
}

func TestNewResourceRecord_NoEncoderWritesNothing(t *testing.T) {
	rr := newRR(t, "x.test.", 60, types.ClassIN, noEncoderType, "a presentation form")
	if got := wireBody(t, rr); len(got) != 0 {
		t.Errorf("WireBody = %x, want nothing", got)
	}
}
