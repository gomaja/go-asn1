// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/contained_tail_policy.go; SHA-256 5bdee01018928224a798dab8155eeb11456c7d3d092aa69315bd179759101ad3.
package uper

import "fmt"

// ContainedBitsPolicy is an explicit receiver choice for bits after a value
// carried in a BIT STRING or OCTET STRING (CONTAINING ...). X.691 (02/2021)
// §11.1.3.2 forbids BIT STRING tails; §11.1.3.1 permits only ordinary
// completion padding in OCTET STRINGs. TS 25.331 V19.0.1 §12.1.3 concerns
// the outer RRC PDU and supplies no corresponding contained-value permission.
type ContainedBitsPolicy struct {
	// Log receives accepted runs on success; it is required when a policy is set.
	Log *ToleranceLog
	// MaxBits bounds the tolerated tail. Zero permits any length; negative
	// values are invalid. Nil DecodeOptions.ContainedBitsTolerance rejects tails.
	MaxBits int
	// ZeroOnly refuses a tail containing any nonzero bit.
	ZeroOnly bool
}

func validateContainedBitsPolicy(policy *ContainedBitsPolicy) error {
	if policy != nil && (policy.Log == nil || policy.MaxBits < 0) {
		return fmt.Errorf("%w: contained bits policy requires a log and nonnegative MaxBits", ErrInvalidValue)
	}
	return nil
}

func (bb *BitBuffer) containedBitsPolicy() *ContainedBitsPolicy {
	if bb.trace == nil {
		return nil
	}
	return bb.trace.containedBits
}

func (bb *BitBuffer) checkContainedTailLength(length int) error {
	policy := bb.containedBitsPolicy()
	if policy == nil || policy.MaxBits > 0 && length > policy.MaxBits {
		return fmt.Errorf("%w: contained value has %d trailing bits", ErrExtraData, length)
	}
	return nil
}

func (bb *BitBuffer) checkContainedTailBits(bits []byte) error {
	if bb.containedBitsPolicy().ZeroOnly {
		for _, octet := range bits {
			if octet != 0 {
				return fmt.Errorf("%w: contained value has nonzero trailing bits", ErrExtraData)
			}
		}
	}
	return nil
}

func (bb *BitBuffer) recordContainedTolerance(kind ToleranceKind, offset int, bits TrailingBits) {
	bb.recordTolerance(kind, offset, bits)
	bb.trace.pending[len(bb.trace.pending)-1].contained = true
}
