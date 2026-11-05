// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/restricted_tolerance.go; SHA-256 8b5c04b31360ce0f8fe2f8eb42071f9383640ed9ae4dc773d205ba6d8feb7699.
package ber

import (
	"fmt"
)

func validAlphabetContents(number int, contents []byte) bool {
	for _, b := range contents {
		if !alphabetOctet(number, b) {
			return false
		}
	}
	return true
}

func checkAlphabetString(number int, contents []byte, source *byte, logicalOffset int, config decodeConfig, options []DecodeOption, preflight bool, position *Violation) error {
	if validAlphabetContents(number, contents) {
		return nil
	}
	if !config.tolerant {
		return fmt.Errorf("%w: %s", ErrInvalidValue, alphabetRule(number))
	}
	return reportStringOctets(number, contents, source, logicalOffset, config, options, preflight, position)
}

func alphabetRuleRef(number int) RuleRef {
	clause := "8.23.5"
	if number == 18 || number == 19 {
		clause = "8.23.4"
	}
	return RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: clause}
}
