// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque.go; SHA-256 ea0da728aaa4f86195a8659eca0b0b72acdd40ff04c7528ddc26c74badfd79be.
package ber

import (
	"errors"
	"fmt"
)

// CheckBEROpaqueElement applies the canonical-opaque override used by generated
// MAP encoders to open values and unknown additions. X.690 (02/2021)
// §§8.13, 8.15, 10, 11: one complete element that already passes the DER checks
// can be copied in a fresh encoding. Unknown IMPLICIT types, foreign DEFAULTs
// and schema-dependent SET ordering cannot be certified without their schema.
// A value requiring repair must instead be supplied through its typed codec.
func CheckBEROpaqueElement(data []byte, options ...EncodeOption) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if !config.noReplay {
		decode := []DecodeOption{encodingStructureOption(data)}
		for _, option := range options {
			if path, ok := option.(constraintPathOption); ok {
				decode = append(decode, path)
			}
		}
		if err := ValidateBERElement(data, decode...); err == nil {
			return nil
		}
		return checkInvalidBEROpaqueElement(data, options, config)
	}
	if err := ValidateDEREncodedElement(data); err != nil {
		cause := fmt.Errorf("%w: opaque element requires a typed value for canonical repair: %w", ErrInvalidValue, err)
		if !errors.Is(err, errInvalidUTF8String) {
			return cause
		}
		return opaqueUTF8EncodeError(data, config.source, options, cause)
	}
	return nil
}

// Diagnostic logs, source lookup and locations are needed only after strict
// validation fails; keeping that work here leaves valid encodes unaffected.
func checkInvalidBEROpaqueElement(data []byte, options []EncodeOption, config encodeConfig) error {
	// X.690 (02/2021) §8.23.10 applies even when the schema of an
	// unknown addition or open value is unavailable to the encoder.
	decode := []DecodeOption{encodingStructureOption(data)}
	var pending ViolationLog
	if config.tolerant && config.violations != nil {
		pending.scope = new(reportScope)
		decode = append(decode, &toleranceOption{violations: &pending})
	}
	for _, option := range options {
		if path, ok := option.(constraintPathOption); ok {
			decode = append(decode, path)
		}
	}
	if config.source != "" {
		decode = LocateDecodedElement(data, config.source, decode)
	}
	if err := ValidateBERElement(data, decode...); err != nil {
		return opaqueUTF8EncodeError(data, config.source, options, err)
	}
	for _, record := range pending.Snapshot() {
		// Encode reports have no received-root coordinate. Keep the octet
		// index privately until publication so distinct bad octets do not
		// collapse while the outer operation reconciles its report stages.
		record.Offset = nil
		record.ChildIndexes = nil
		record.encodeRecord = true
		record.scope = config.reportScope
		if err := config.violations.append(record, DefaultDiagnosticLimits()); err != nil {
			return err
		}
	}
	return nil
}

// An invalid UTF8String is a value violation even when the enclosing type is
// opaque. Re-scan only failed encodes to retain the same X.690 §8.23.10 record
// as tolerant decoding; unrelated structural failures keep their original kind.
func opaqueUTF8EncodeError(data []byte, source string, options []EncodeOption, cause error) error {
	if !errors.Is(cause, ErrInvalidValue) {
		return cause
	}
	var reports ViolationLog
	decode := []DecodeOption{encodingStructureOption(data), WithTolerance(&reports)}
	for _, option := range options {
		if path, ok := option.(constraintPathOption); ok {
			decode = append(decode, path)
		}
	}
	if source != "" {
		decode = LocateDecodedElement(data, source, decode)
	}
	if err := ValidateBERElement(data, decode...); err != nil {
		return cause
	}
	records := reports.Snapshot()
	if len(records) == 0 || records[0].Rule.Clause != "8.23.10" {
		return cause
	}
	record := records[0]
	record.Offset, record.OctetOffset, record.ChildIndexes = nil, nil, nil
	return &ValidationError{boundedViolation(record)}
}
