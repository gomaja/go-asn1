// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_encode.go; SHA-256 301ff266bc4397809c14322523d914a8384ba2ad4bf8421bd60c0deaab946306.
package ber

import (
	"fmt"
	"unicode/utf8"
)

// The private cause identifies the failed DER rule without classifying error text.
var errInvalidUTF8String = fmt.Errorf("%w: DER universal tag 12: UTF8String violates its encoding or repertoire rules", ErrInvalidValue)

// X.690 (02/2021) §8.23.10: check the typed string before encoding. No TLV
// is constructed or parsed to obtain a diagnostic, and valid values need no
// path, source options, diagnostic log or per-octet records.
func checkEncodedUTF8String(value string, options []EncodeOption, component string) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if validUTF8Contents([]byte(value)) {
		return nil
	}
	path := qualifyConstraintPath(options, component)
	source := sourceField(config.source, component)
	var controls stringControlState
	for offset := 0; offset < len(value); {
		r, size := utf8.DecodeRuneInString(value[offset:])
		forbidden := controls.consume(12, r)
		// ISO/IEC 10646:2003 §§7 a), 8 exclude permanently reserved noncharacters.
		if r == utf8.RuneError && size == 1 || isUnicodeNoncharacter(r) || forbidden {
			octet := offset
			record := Violation{
				Rule: RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"},
				Path: path, Source: source,
				Constraint:    "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)",
				ObservedValue: fmt.Sprintf("%02x", value[offset]), OctetOffset: &octet,
				encodeRecord: true, scope: config.reportScope,
			}
			if isUnicodeNoncharacter(r) {
				record.Rule, record.Constraint = unicodeNoncharacterRule(), unicodeNoncharacterConstraint
			}
			if forbidden {
				record.Constraint = stringControlConstraint(12)
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
