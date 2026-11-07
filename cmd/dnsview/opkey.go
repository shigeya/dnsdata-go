package main

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/verifier"
	"github.com/shigeya/dnsdata-go/zone"
)

// opkeyView is the "opkey" member of a line under -opkey: the records
// of a validated TLSA (or, once allocated, OPKEY) answer read as OPKEY
// RDATA (draft-shigeya-dns-opkey-00). Error is set, and Records is
// empty, when a record is not valid TLSA RDATA at all; that fails the
// whole RRset, as zone.OPKEYFromTLSA does.
type opkeyView struct {
	Records []opkeyRecord `json:"records"`
	Error   string        `json:"error,omitempty"`
}

// opkeyRecord is one record of the answer: its OPKEY presentation form,
// whether a verifier may use it (draft §2.1), and if not, why.
type opkeyRecord struct {
	Value  string `json:"value"`
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
}

// carriesOPKEY reports whether an answer of type t holds OPKEY RDATA:
// TLSA (the transitional form, draft §4.1) or the OPKEY type once its
// value is allocated.
func carriesOPKEY(t uint16) bool {
	if t == types.TypeTLSA {
		return true
	}
	opkey, err := types.OPKEYType()
	return err == nil && t == opkey
}

// readOPKEY returns the OPKEY view of res, or nil when res has no
// validated answer of a type that carries OPKEY RDATA. Only a secure
// answer carries records (verifier.Result.Answer), so a record that is
// shown has been validated.
func readOPKEY(res *verifier.Result) *opkeyView {
	if res == nil || res.Answer == nil || !carriesOPKEY(res.Answer.Type) {
		return nil
	}
	records := make([]opkeyRecord, 0, len(res.Answer.Records))
	for i, r := range res.Answer.Records {
		k, err := zone.DecodeOPKEYRData(r.RData)
		if err != nil {
			return &opkeyView{Records: []opkeyRecord{}, Error: fmt.Sprintf("record %d: %v", i, err)}
		}
		records = append(records, opkeyRecordOf(k))
	}
	return &opkeyView{Records: records}
}

func opkeyRecordOf(k zone.OPKEY) opkeyRecord {
	err := k.Check()
	if err == nil {
		return opkeyRecord{Value: k.String(), Usable: true}
	}
	reason := strings.TrimPrefix(err.Error(), zone.ErrRDataFormat.Error()+": ")
	return opkeyRecord{Value: k.String(), Reason: reason}
}
