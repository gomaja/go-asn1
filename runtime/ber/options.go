package ber

import "fmt"

// DecodeLimits bound BER work on untrusted input. Zero fields retain the
// defaults. X.690 (02/2021) places no depth or size ceiling on BER; callers
// can raise these operational limits for a trusted protocol profile.
type DecodeLimits struct {
	MaxDepth    int // constructed nesting levels
	MaxElements int // TLVs examined while scanning a constructed value
	MaxWork     int // aggregate encoded bytes visited by constructed decoders
}

// DefaultDecodeLimits returns the limits used when no option is supplied.
// They exceed the largest committed release vector (529 bytes) by a wide
// margin while bounding both nesting and aggregate parsing work.
func DefaultDecodeLimits() DecodeLimits {
	return DecodeLimits{MaxDepth: 128, MaxElements: 100000, MaxWork: 16 << 20}
}

// DecodeOption configures a BER decode entry point.
type DecodeOption func(*DecodeLimits)

// WithDecodeLimits overrides the nonzero limit fields. Supply the same option
// to a generated UnmarshalBER entry point to admit a larger BER profile.
func WithDecodeLimits(limits DecodeLimits) DecodeOption {
	return func(dst *DecodeLimits) {
		if limits.MaxDepth != 0 {
			dst.MaxDepth = limits.MaxDepth
		}
		if limits.MaxElements != 0 {
			dst.MaxElements = limits.MaxElements
		}
		if limits.MaxWork != 0 {
			dst.MaxWork = limits.MaxWork
		}
	}
}

func decodeLimits(options []DecodeOption) (DecodeLimits, error) {
	limits := DefaultDecodeLimits()
	for _, option := range options {
		if option == nil {
			return limits, fmt.Errorf("%w: nil BER decode option", ErrInvalidValue)
		}
		option(&limits)
	}
	if limits.MaxDepth <= 0 || limits.MaxElements <= 0 || limits.MaxWork <= 0 {
		return limits, fmt.Errorf("%w: BER decode limits must be positive", ErrInvalidValue)
	}
	return limits, nil
}

// encodingStructureOption permits validation of a caller-supplied value
// without applying the untrusted-input decode budget to encoding.
func encodingStructureOption(data []byte) DecodeOption {
	bound := max(1, len(data))
	return WithDecodeLimits(DecodeLimits{MaxDepth: bound, MaxElements: bound, MaxWork: bound})
}
