package verifier

import (
	"fmt"
	"time"

	"github.com/shigeya/dnsdata-go/dnssec"
	"github.com/shigeya/dnsdata-go/wire"
)

// buildAnswer describes the (qname, qtype) RRset of z, which has just
// verified, with every RRSIG over it that verifies on its own.
func buildAnswer(z *dnssec.Zone, qname string, qtype uint16) (*Answer, error) {
	rrset := z.FindRRSet(qname, qtype)
	a := &Answer{Name: qname, Type: qtype, Records: make([]AnswerRecord, 0, len(rrset))}
	for _, rr := range rrset {
		var b wire.Builder
		if err := rr.WireBody(&b); err != nil {
			return nil, fmt.Errorf("%w: answer %s: %v", ErrVerifier, rr.Label, err)
		}
		a.Records = append(a.Records, AnswerRecord{
			Name:  rr.Label,
			TTL:   rr.TTL,
			Class: rr.Class,
			Type:  rr.Type,
			Value: rr.Value,
			RData: b.Clone()[2:], // drop RDLENGTH
		})
	}
	for _, sig := range z.FindRRSIGs(qname, qtype, "") {
		ok, err := z.VerifyRRSIG(qname, qtype, sig, dnssec.KeyModeNone)
		if err != nil || !ok {
			continue
		}
		a.Signatures = append(a.Signatures, AnswerSignature{
			KeyTag:     sig.KeyTag,
			Algorithm:  sig.Algorithm,
			Signer:     sig.Signer,
			Labels:     sig.Labels,
			Inception:  time.Unix(sig.Inception, 0).UTC(),
			Expiration: time.Unix(sig.Expire, 0).UTC(),
		})
	}
	return a, nil
}
