// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/string_controls_encode.go; SHA-256 503dda892b5a6657dd2d08ab6c3ae59975510a066d2164f34ca10e8aa5c7a862.
package ber

import "fmt"

// X.690 (02/2021) §8.23.5.3/Table 3: generated IA5String encoders
// check complete escape sequences separately from repertoire/FROM constraints.
func checkEncodedIA5Controls(value string, options []EncodeOption, component string) error {
	if validStringControls(22, value) {
		return nil
	}
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	path := qualifyConstraintPath(options, component)
	source := sourceField(config.source, component)
	var controls stringControlState
	for offset, r := range value {
		if !controls.consume(22, r) {
			continue
		}
		octet := offset
		record := Violation{
			Rule: RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.5.3"},
			Path: path, Source: source, Constraint: stringControlConstraint(22),
			ObservedValue: fmt.Sprintf("%02x", value[offset]), OctetOffset: &octet,
			encodeRecord: true, scope: config.reportScope,
		}
		if !config.tolerant {
			record.OctetOffset = nil
			return &ValidationError{boundedViolation(record)}
		}
		if err := config.violations.append(record, DefaultDiagnosticLimits()); err != nil {
			return err
		}
	}
	return nil
}
