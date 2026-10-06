package dnssec

import (
	"errors"
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
	// key tag and algorithm, or none of those keys is accepted in the
	// requested [KeyVerifyMode] (e.g. in KeyModeKSK, a key that is
	// neither trusted nor matched by a parent DS).
	SigNoMatchingKey
	// SigInvalid: the signature does not verify over the rrset under
	// any accepted key, or the key or signature is malformed, or the
	// covered rrset is absent.
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
// status: validity window (only with a clock, [Zone.SetClock]); key
// lookup by signer, key tag and algorithm ([Zone.FindDNSKeys]); key
// mode, which keeps the candidate keys that mode accepts
// ([SigNoMatchingKey] when none is left); signature. The signature is
// always checked, in every mode, and verifies when it verifies under
// any one of the remaining keys; otherwise the status and error are
// those of the first key.
func (z *Zone) CheckRRSIG(name string, typeCovered uint16, rrsig *RRSig, mode KeyVerifyMode) (SigStatus, error) {
	if s := z.validityStatus(rrsig); s != SigVerified {
		return s, nil
	}
	keys, err := z.keysForMode(z.FindDNSKeys(rrsig.Signer, rrsig.KeyTag, rrsig.Algorithm), mode)
	if len(keys) == 0 {
		return SigNoMatchingKey, err
	}
	digestTarget, err := z.CreateDigestTarget(rrsig, name, typeCovered)
	if err != nil {
		return SigInvalid, err
	}
	if digestTarget == nil {
		return SigInvalid, nil
	}
	return verifyWithAny(keys, digestTarget, rrsig.Signature)
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

// keysForMode keeps the candidate keys (all with the RRSIG's signer,
// key tag and algorithm) that mode accepts as signers, with the first
// error met while deciding. No key's SEP flag is consulted.
//
//   - KeyModeNone: every key.
//   - KeyModeKSK: the authenticated KSKs ([Zone.AddTrustedKey], or a
//     DS match in the parent).
//   - KeyModeZSK: every key, when the DNSKEY rrset at the signer (which
//     holds them all) verifies in KeyModeKSK; otherwise none.
//   - KeyModeCSK: as KeyModeZSK, or else the authenticated KSKs.
//   - any other value: none.
func (z *Zone) keysForMode(keys []*DNSKey, mode KeyVerifyMode) ([]*DNSKey, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	switch mode {
	case KeyModeNone:
		return keys, nil
	case KeyModeKSK:
		return z.filterKeys(keys, z.verifyKSK)
	case KeyModeZSK:
		if ok, err := z.verifyZSK(keys[0]); !ok {
			return nil, err
		}
		return keys, nil
	case KeyModeCSK:
		ok, zskErr := z.verifyZSK(keys[0])
		if ok {
			return keys, nil
		}
		ksks, err := z.filterKeys(keys, z.verifyKSK)
		return ksks, errors.Join(zskErr, err)
	}
	return nil, nil
}

// filterKeys keeps the keys accept reports true for, with the first
// error accept returned.
func (z *Zone) filterKeys(keys []*DNSKey, accept func(*DNSKey) (bool, error)) ([]*DNSKey, error) {
	var out []*DNSKey
	var firstErr error
	for _, k := range keys {
		ok, err := accept(k)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if ok {
			out = append(out, k)
		}
	}
	return out, firstErr
}

// verifyWithAny checks signature over data under each key in turn:
// SigVerified as soon as one verifies, otherwise the status and error
// of the first key.
func verifyWithAny(keys []*DNSKey, data, signature []byte) (SigStatus, error) {
	var status SigStatus
	var firstErr error
	for i, k := range keys {
		ok, err := k.Verify(data, signature)
		if ok && err == nil {
			return SigVerified, nil
		}
		if i == 0 {
			status, firstErr = verifyStatus(ok, err), err
		}
	}
	return status, firstErr
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
