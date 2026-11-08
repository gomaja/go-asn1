// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque.go; SHA-256 90a391f2e7727f03c23de4031c3aafd1240abc66f8201241a3eafb6b2d6b9e13.
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
// opaque. Re-scan only failed encodes to retain the same encoding or repertoire record
// as tolerant decoding; unrelated structural failures keep their original kind.
func opaqueUTF8EncodeError(data []byte, source string, options []EncodeOption, cause error) error {
	if !errors.Is(cause, ErrInvalidValue) {
		return cause
	}
	var reports ViolationLog
	decode := []DecodeOption{encodingStructureOption(data), WithTolerance(&reports), decodeOptionFunc(func(config *decodeConfig) error {
		config.firstUTF8Only = true
		return nil
	})}
	for _, option := range options {
		if path, ok := option.(constraintPathOption); ok {
			decode = append(decode, path)
		}
	}
	if source != "" {
		decode = LocateDecodedElement(data, source, decode)
	}
	if err := ValidateBERElement(data, decode...); err != nil {
		return err
	}
	records := reports.Snapshot()
	if len(records) == 0 {
		return cause
	}
	// X.690 (02/2021) §8.23.10 and ISO/IEC 10646:2003 §§7 a), 8
	// give UTF8String both encoding and repertoire requirements.
	rule := records[0].Rule
	if rule != (RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}) && rule != unicodeNoncharacterRule() {
		return cause
	}
	record := records[0]
	record.Offset, record.OctetOffset, record.ChildIndexes = nil, nil, nil
	return &ValidationError{boundedViolation(record)}
}
