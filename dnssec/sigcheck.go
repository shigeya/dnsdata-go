package dnssec

import (
	"errors"

	"github.com/shigeya/dnsdata-go/types"
)

// SigStatus classifies the outcome of checking one RRSIG
// ([Zone.CheckRRSIG]). Its String form is the stable, kebab-case name
// used in JSON by the verifier package.
type SigStatus uint8

const (
	// SigVerified: the signature verified (in the requested key mode).
	SigVerified SigStatus = iota
	// SigExpired: the zone's clock is after the RRSIG's expiration.
	SigExpired
	// SigNotYetValid: the zone's clock is before the RRSIG's inception.
	SigNotYetValid
	// SigUnsupportedAlgorithm: the signing key uses an algorithm this
	// package does not implement ([ErrUnsupportedAlgorithm]).
	SigUnsupportedAlgorithm
	// SigNoMatchingKey: no DNSKEY at the signer name has the RRSIG's
	// key tag, or the key found is not authenticated in the requested
	// [KeyVerifyMode] (e.g. a KSK whose digest matches no parent DS).
	SigNoMatchingKey
	// SigInvalid: the signature does not verify over the rrset, or the
	// key or signature is malformed, or the covered rrset is absent.
	SigInvalid
)

var sigStatusNames = [...]string{
	SigVerified:             "verified",
	SigExpired:              "expired",
	SigNotYetValid:          "not-yet-valid",
	SigUnsupportedAlgorithm: "unsupported-algorithm",
	SigNoMatchingKey:        "no-matching-key",
	SigInvalid:              "invalid",
}

// String returns "verified", "expired", "not-yet-valid",
// "unsupported-algorithm", "no-matching-key" or "invalid".
func (s SigStatus) String() string {
	if int(s) < len(sigStatusNames) {
		return sigStatusNames[s]
	}
	return "invalid"
}

// SigResult is the outcome of checking one RRSIG of an rrset
// ([Zone.CheckRRSet]). Err is non-nil when the check could not be
// carried out (the same errors [Zone.VerifyRRSIG] returns).
type SigResult struct {
	RRSig  *RRSig
	Status SigStatus
	Err    error
}

// CheckRRSIG checks one RRSIG against the rrset it covers, like
// [Zone.VerifyRRSIG], and reports why it failed. VerifyRRSIG returns
// (status == SigVerified, err) for the same arguments.
//
// The checks run in this order, the first failing one deciding the
// status: validity window (only with a clock, [Zone.SetClock]), key
// lookup by signer and key tag, key mode, signature.
func (z *Zone) CheckRRSIG(name string, typeCovered uint16, rrsig *RRSig, mode KeyVerifyMode) (SigStatus, error) {
	if s := z.validityStatus(rrsig); s != SigVerified {
		return s, nil
	}
	dnskey := z.FindDNSKey(rrsig.Signer, rrsig.KeyTag)
	if dnskey == nil {
		return SigNoMatchingKey, nil
	}
	if done, s, err := z.checkKeyMode(dnskey, typeCovered, mode); done {
		return s, err
	}
	digestTarget, err := z.CreateDigestTarget(rrsig, name, typeCovered)
	if err != nil {
		return SigInvalid, err
	}
	if digestTarget == nil {
		return SigInvalid, nil
	}
	ok, err := dnskey.Verify(digestTarget, rrsig.Signature)
	return verifyStatus(ok, err), err
}

// CheckRRSet checks every RRSIG over (name, typeCovered), optionally
// filtered by signer, and returns one result per RRSIG in zone order.
// Unlike [Zone.VerifyRRSet] it does not stop at the first signature
// that verifies. [RRSetVerified] folds the results into VerifyRRSet's
// answer.
func (z *Zone) CheckRRSet(name string, typeCovered uint16, mode KeyVerifyMode, signer string) []SigResult {
	sigs := z.FindRRSIGs(name, typeCovered, signer)
	out := make([]SigResult, 0, len(sigs))
	for _, sig := range sigs {
		s, err := z.CheckRRSIG(name, typeCovered, sig, mode)
		out = append(out, SigResult{RRSig: sig, Status: s, Err: err})
	}
	return out
}

// RRSetVerified applies RFC 4035 §5.3.3 "any-valid" semantics to
// results: (true, nil) when one signature verified, otherwise false
// with the first error met (nil when none). This is what
// [Zone.VerifyRRSet] returns for the same rrset.
func RRSetVerified(results []SigResult) (bool, error) {
	var firstErr error
	for _, r := range results {
		if r.Status == SigVerified {
			return true, nil
		}
		if firstErr == nil {
			firstErr = r.Err
		}
	}
	return false, firstErr
}

// validityStatus places the zone's clock against rrsig's window (both
// ends inclusive). SigVerified means inside, or no clock set.
func (z *Zone) validityStatus(rrsig *RRSig) SigStatus {
	if z.now == nil {
		return SigVerified
	}
	t := z.now().Unix()
	switch {
	case t < rrsig.Inception:
		return SigNotYetValid
	case t > rrsig.Expire:
		return SigExpired
	}
	return SigVerified
}

// checkKeyMode applies the extra key-chain checks of mode to dnskey.
// done reports that the outcome is decided without checking the
// signature itself.
//
// In KeyModeKSK a secure-entry-point key authenticated against the
// parent DS (or a configured SEP) decides an RRSIG over the DNSKEY
// rrset as verified without checking the signature octets. This is the
// behaviour VerifyRRSIG has always had; CheckRRSIG keeps it so the two
// agree.
func (z *Zone) checkKeyMode(dnskey *DNSKey, typeCovered uint16, mode KeyVerifyMode) (done bool, s SigStatus, err error) {
	sep := dnskey.IsSecureEntryPoint()
	switch {
	case mode == KeyModeZSK && !sep:
		if ok, err := z.verifyZSK(dnskey); err != nil || !ok {
			return true, SigNoMatchingKey, err
		}
	case (mode == KeyModeKSK || mode == KeyModeCSK) && sep:
		if ok, err := z.verifyKSK(dnskey); err != nil || !ok {
			return true, SigNoMatchingKey, err
		}
		if mode == KeyModeKSK && typeCovered == types.TypeDNSKEY {
			return true, SigVerified, nil
		}
	}
	return false, SigVerified, nil
}

// verifyStatus maps [DNSKey.Verify]'s result to a status.
func verifyStatus(ok bool, err error) SigStatus {
	switch {
	case errors.Is(err, ErrUnsupportedAlgorithm):
		return SigUnsupportedAlgorithm
	case err != nil || !ok:
		return SigInvalid
	}
	return SigVerified
}
