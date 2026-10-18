// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/options.go; SHA-256 317f731250a3b947c262ec430dd09c3071416cbe28f220b8562426057478fb7b.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"strings"
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

// DiagnosticLimits bounds tolerance records produced by one decode operation.
// Zero fields retain the defaults. These are operational limits, not additional
// wire restrictions in X.690 (02/2021) §8.23.10.
type DiagnosticLimits struct {
	MaxRecords       int
	MaxObservedBytes int // total bytes retained in ObservedValue strings
}

// DefaultDiagnosticLimits permits 1024 reports and 64 KiB of observed values
// per decode. Each observed value is also capped by MaxObservedValueBytes.
func DefaultDiagnosticLimits() DiagnosticLimits {
	return DiagnosticLimits{MaxRecords: 1024, MaxObservedBytes: 64 << 10}
}

// WithDiagnosticLimits overrides nonzero diagnostic limits. A generated decode
// shares the budget across preflight, typed checks and nested calls. Exhaustion
// returns ErrResourceLimit; diagnostics are never silently dropped.
func WithDiagnosticLimits(limits DiagnosticLimits) DecodeOption {
	return decodeOptionFunc(func(config *decodeConfig) error {
		if limits.MaxRecords != 0 {
			config.diagnostics.MaxRecords = limits.MaxRecords
		}
		if limits.MaxObservedBytes != 0 {
			config.diagnostics.MaxObservedBytes = limits.MaxObservedBytes
		}
		return nil
	})
}

// DecodeOption configures a BER decode entry point.
type DecodeOption interface{ applyDecode(*decodeConfig) error }

type decodeOptionFunc func(*decodeConfig) error

func (option decodeOptionFunc) applyDecode(config *decodeConfig) error { return option(config) }

type decodeConfig struct {
	checkReplayComparator bool
	profile               bool
	profileNested         bool
	profileType           string
	profileSource         string
	positionSearch        *positionSearch
	collectPositionsOnly  bool
	location              *decodeLocation
	noReplayCapture       bool
	limits                DecodeLimits
	diagnostics           DiagnosticLimits
	tolerant              bool
	violations            *ViolationLog
	reportScope           *reportScope
	hasPath               bool
	form                  *berFormState
	collectionSizeChecked bool
	generatedMode         generatedDecodeMode
}

type generatedDecodeMode uint8

const (
	generatedModeAdaptive generatedDecodeMode = iota
	generatedModeLight
	generatedModeProof
)

type generatedModeOption struct{ mode generatedDecodeMode }

func (option generatedModeOption) applyDecode(config *decodeConfig) error {
	config.generatedMode = option.mode
	return nil
}

// ForceGeneratedBERLightForTesting exercises the ordinary nested-validation
// path in differential tests. It must not be used by production callers.
func ForceGeneratedBERLightForTesting() DecodeOption { return generatedModeOption{generatedModeLight} }

// ForceGeneratedBERProofForTesting exercises the validated-span path in
// differential tests. It must not be used by production callers.
func ForceGeneratedBERProofForTesting() DecodeOption { return generatedModeOption{generatedModeProof} }

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
	// Keep the default path separate from the config passed through option
	// interfaces, whose implementations may retain its address.
	if len(options) == 0 {
		return decodeConfig{limits: DefaultDecodeLimits(), diagnostics: DefaultDiagnosticLimits()}, nil
	}
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok {
			if err := context.validate(); err != nil {
				return decodeConfig{}, err
			}
			return validateDecodeConfig(context.config)
		}
	}
	config := decodeConfig{limits: DefaultDecodeLimits(), diagnostics: DefaultDiagnosticLimits()}
	for _, option := range options {
		switch value := option.(type) {
		case constraintPathOption:
			if value == "" || strings.Contains(string(value), ".") {
				return config, fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
			}
			config.collectionSizeChecked = false
			config.hasPath = true
		case encodingStructureLimitsOption:
			config.limits.MaxDepth, config.limits.MaxElements, config.limits.MaxWork = value.bound, value.bound, value.bound
		case tcapEncodedProfileOption:
			if err := value.applyDecode(&config); err != nil {
				return config, err
			}
		case generatedModeOption:
			config.generatedMode = value.mode
		case tcapProfileOption:
			config.profile = true
			config.profileNested = value.nested
			config.profileType = value.source
			config.profileSource = value.ruleSource
		case decodeLocationOption:
			config.location = value.location
		case *generatedDecodeOption:
			if err := value.validate(); err != nil {
				return config, err
			}
			config = value.config
		case diagnosticChildOption:
			if err := value.applyDecode(&config); err != nil {
				return config, err
			}
		case *toleranceOption:
			if err := value.applyDecode(&config); err != nil {
				return config, err
			}
		case berFormOption:
			config.form = value.state
		case parentCollectionSizeOption:
			config.collectionSizeChecked = true
		default:
			return decodeOptionsWithCustom(options)
		}
	}
	return validateDecodeConfig(config)
}

func decodeOptionsWithCustom(options []DecodeOption) (decodeConfig, error) {
	config := decodeConfig{limits: DefaultDecodeLimits(), diagnostics: DefaultDiagnosticLimits()}
	for _, option := range options {
		if option == nil {
			return config, fmt.Errorf("%w: nil BER decode option", ErrInvalidValue)
		}
		if err := option.applyDecode(&config); err != nil {
			return config, err
		}
	}
	return validateDecodeConfig(config)
}

func validateDecodeConfig(config decodeConfig) (decodeConfig, error) {
	if config.limits.MaxDepth <= 0 || config.limits.MaxElements <= 0 || config.limits.MaxWork <= 0 {
		return config, fmt.Errorf("%w: BER decode limits must be positive", ErrInvalidValue)
	}
	if config.limits.MaxRealDecimalDigits < 0 {
		return config, fmt.Errorf("%w: REAL decimal digit limit must be nonnegative", ErrInvalidValue)
	}
	if config.diagnostics.MaxRecords <= 0 || config.diagnostics.MaxObservedBytes <= 0 {
		return config, fmt.Errorf("%w: BER diagnostic limits must be positive", ErrInvalidValue)
	}
	return config, nil
}

// ValidateDecodeOptions rejects malformed options before reading any BER data.
// It uses the runtime's authoritative option validation without reading input
// or publishing constraint reports.
func ValidateDecodeOptions(options ...DecodeOption) error {
	_, err := decodeOptions(options)
	return err
}

func decodeLimits(options []DecodeOption) (DecodeLimits, error) {
	config, err := decodeOptions(options)
	return config.limits, err
}

// encodingStructureOption permits validation of a caller-supplied value
// without applying the untrusted-input decode budget to encoding.
func encodingStructureOption(data []byte) DecodeOption {
	return encodingStructureLimitsOption{bound: max(1, len(data))}
}

type encodingStructureLimitsOption struct{ bound int }

func (option encodingStructureLimitsOption) applyDecode(config *decodeConfig) error {
	config.limits.MaxDepth, config.limits.MaxElements, config.limits.MaxWork = option.bound, option.bound, option.bound
	return nil
}

// DecodeEncodedTLV reads one TLV of a value being encoded, such as a retained
// unknown extension or a nested encoding the encoder re-wraps. Its limits
// scale with data instead of the untrusted-input defaults, so a value that a
// caller decoded under raised limits can be encoded again; X.690 (02/2021)
// §§8.1.3 and 8.7 place no ceiling on BER nesting.
func DecodeEncodedTLV(data []byte) (tag.Tag, int, []byte, error) {
	bound := max(1, len(data))
	return decodeTLV(data, DecodeLimits{MaxDepth: bound, MaxElements: bound, MaxWork: bound}, nil)
}
