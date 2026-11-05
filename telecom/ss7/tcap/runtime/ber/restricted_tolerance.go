// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/restricted_tolerance.go; SHA-256 f75649ff9ce3e1de748956189a77ca89432a40d17a4ea688f4b0caf9c949ccab.
package ber

import (
	"fmt"
	"weak"
)

func validAlphabetContents(number int, contents []byte) bool {
	for _, b := range contents {
		if !alphabetOctet(number, b) {
			return false
		}
	}
	return true
}

func checkAlphabetString(number int, contents []byte, source *byte, logicalOffset int, config decodeConfig, options []DecodeOption, preflight bool) error {
	if validAlphabetContents(number, contents) {
		return nil
	}
	if !config.tolerant || config.profile {
		return fmt.Errorf("%w: %s", ErrInvalidValue, alphabetRule(number))
	}
	path := qualifyConstraintPath(options, "")
	// Each out-of-alphabet octet has its own bounded report. Logical offsets
	// continue across OCTET STRING segments (X.690 (02/2021) §8.23.3).
	for offset := 0; offset < len(contents); {
		size := 1
		if !alphabetOctet(number, contents[offset]) {
			location := logicalOffset + offset
			if err := config.violations.append(Violation{
				Rule: alphabetRuleRef(number), Path: path, Constraint: alphabetRule(number),
				ObservedValue: fmt.Sprintf("%02x", contents[offset]), OctetOffset: &location,
				source: weak.Make(source), preflight: preflight, scope: config.reportScope,
			}, config.diagnostics); err != nil {
				return err
			}
		}
		offset += size
	}
	if config.form != nil {
		config.form.preserve = true
	}
	return nil
}

func alphabetRuleRef(number int) RuleRef {
	clause := "8.23.5"
	if number == 18 || number == 19 {
		clause = "8.23.4"
	}
	return RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: clause}
}
