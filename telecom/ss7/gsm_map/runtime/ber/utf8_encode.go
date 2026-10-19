// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_encode.go; SHA-256 346200f8cf9f2f387c5ced23a2417eebf26d1c98a5a81aa131b01e4cf2d72e2f.
package ber

import (
	"fmt"
	"unicode/utf8"
)

// The private cause identifies the failed DER rule without classifying error text.
var errInvalidUTF8String = fmt.Errorf("%w: DER universal tag 12: UTF8String is not shortest-form UTF-8 scalar text", ErrInvalidValue)

// X.690 (02/2021) §8.23.10: check the typed string before encoding. No TLV
// is constructed or parsed to obtain a diagnostic, and valid values need no
// path, source options, diagnostic log or per-octet records.
func checkEncodedUTF8String(value string, options []EncodeOption, component string) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if utf8.ValidString(value) {
		return nil
	}
	path := qualifyConstraintPath(options, component)
	source := sourceField(config.source, component)
	for offset := 0; offset < len(value); {
		r, size := utf8.DecodeRuneInString(value[offset:])
		if r == utf8.RuneError && size == 1 {
			octet := offset
			record := Violation{
				Rule: RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"},
				Path: path, Source: source,
				Constraint:    "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)",
				ObservedValue: fmt.Sprintf("%02x", value[offset]), OctetOffset: &octet,
				encodeRecord: true, scope: config.reportScope,
			}
			if !config.tolerant || config.noReplay {
				record.OctetOffset = nil
				return &ValidationError{boundedViolation(record)}
			}
			if err := config.violations.append(record, DefaultDiagnosticLimits()); err != nil {
				return err
			}
		}
		offset += size
	}
	return nil
}
