package ber

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// DecodeLimits bound BER work on untrusted input. Zero fields retain the
// defaults. X.690 (02/2021) places no depth or size ceiling on BER; callers
// can raise these operational limits for a trusted protocol profile.
type DecodeLimits struct {
	MaxDepth    int // constructed nesting levels
	MaxElements int // TLVs examined while scanning a constructed value
	MaxWork     int // aggregate encoded bytes visited by constructed decoders
	// MaxRealDecimalDigits bounds the total received mantissa and exponent
	// digits in each decimal REAL, including leading zeros. Zero is unlimited.
	// This is an operational limit, not an X.690 (02/2021) §8.5.8 restriction.
	MaxRealDecimalDigits int
}

// DefaultDecodeLimits returns the limits used when no option is supplied.
// They exceed the largest committed release vector (529 bytes) by a wide
// margin while bounding both nesting and aggregate parsing work.
func DefaultDecodeLimits() DecodeLimits {
	return DecodeLimits{MaxDepth: 128, MaxElements: 100000, MaxWork: 16 << 20}
}

// DecodeOption configures a BER decode entry point.
type DecodeOption interface{ applyDecode(*decodeConfig) error }

type decodeOptionFunc func(*decodeConfig) error

func (option decodeOptionFunc) applyDecode(config *decodeConfig) error { return option(config) }

type decodeConfig struct {
	limits     DecodeLimits
	tolerant   bool
	violations *ViolationLog
	path       string
	form       *berFormState
}

// WithDecodeLimits overrides the nonzero limit fields. Supply the same option
// to a generated UnmarshalBER entry point to admit a larger BER profile.
func WithDecodeLimits(limits DecodeLimits) DecodeOption {
	return decodeOptionFunc(func(config *decodeConfig) error {
		dst := &config.limits
		if limits.MaxDepth != 0 {
			dst.MaxDepth = limits.MaxDepth
		}
		if limits.MaxElements != 0 {
			dst.MaxElements = limits.MaxElements
		}
		if limits.MaxWork != 0 {
			dst.MaxWork = limits.MaxWork
		}
		if limits.MaxRealDecimalDigits != 0 {
			dst.MaxRealDecimalDigits = limits.MaxRealDecimalDigits
		}
		return nil
	})
}

func decodeOptions(options []DecodeOption) (decodeConfig, error) {
	config := decodeConfig{limits: DefaultDecodeLimits()}
	for _, option := range options {
		if option == nil {
			return config, fmt.Errorf("%w: nil BER decode option", ErrInvalidValue)
		}
		if err := option.applyDecode(&config); err != nil {
			return config, err
		}
	}
	if config.limits.MaxDepth <= 0 || config.limits.MaxElements <= 0 || config.limits.MaxWork <= 0 {
		return config, fmt.Errorf("%w: BER decode limits must be positive", ErrInvalidValue)
	}
	if config.limits.MaxRealDecimalDigits < 0 {
		return config, fmt.Errorf("%w: REAL decimal digit limit must be nonnegative", ErrInvalidValue)
	}
	return config, nil
}

func decodeLimits(options []DecodeOption) (DecodeLimits, error) {
	config, err := decodeOptions(options)
	return config.limits, err
}

// encodingStructureOption permits validation of a caller-supplied value
// without applying the untrusted-input decode budget to encoding.
func encodingStructureOption(data []byte) DecodeOption {
	bound := max(1, len(data))
	return WithDecodeLimits(DecodeLimits{MaxDepth: bound, MaxElements: bound, MaxWork: bound})
}

// DecodeEncodedTLV reads one TLV of a value being encoded, such as a retained
// unknown extension or a nested encoding the encoder re-wraps. Its limits
// scale with data instead of the untrusted-input defaults, so a value that a
// caller decoded under raised limits can be encoded again; X.690 (02/2021)
// §§8.1.3 and 8.7 place no ceiling on BER nesting.
func DecodeEncodedTLV(data []byte) (tag.Tag, int, []byte, error) {
	return DecodeTLV(data, encodingStructureOption(data))
}
