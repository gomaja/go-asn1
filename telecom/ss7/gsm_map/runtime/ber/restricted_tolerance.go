// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/restricted_tolerance.go; SHA-256 3785403de6108d01ed0930084dcb2a03eb074576002de8b5fb4e57c52fd46e5a.
package ber

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func validAlphabetContentsState(number int, contents []byte, controls *stringControlState) bool {
	valid := true
	for _, b := range contents {
		forbidden := number == tag.TagIA5String && controls.consume(number, rune(b))
		if !alphabetOctet(number, b) || forbidden {
			valid = false
		}
	}
	return valid
}

func checkAlphabetString(number int, contents []byte, source *byte, logicalOffset int, config decodeConfig, options []DecodeOption, preflight bool, position *Violation, initial ...stringControlState) error {
	controls := stringControlState{}
	if len(initial) != 0 {
		controls = initial[0]
	}
	if validAlphabetContentsState(number, contents, &controls) {
		return nil
	}
	if !config.tolerant {
		return fmt.Errorf("%w: %s", ErrInvalidValue, alphabetRule(number))
	}
	return reportStringOctets(number, contents, source, logicalOffset, config, options, preflight, position, initial...)
}

func alphabetRuleRef(number int) RuleRef {
	clause := "8.23.5"
	if number == 18 || number == 19 {
		clause = "8.23.4"
	}
	return RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: clause}
}
