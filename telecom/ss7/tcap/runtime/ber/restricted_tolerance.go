// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/restricted_tolerance.go; SHA-256 23b3be780890d76f676cdc6c4580449c100d0263a71678449ce6e7dd2f3bcc17.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
)

func validAlphabetContents(number int, contents []byte) bool {
	var controls stringControlState
	return validAlphabetContentsState(number, contents, &controls)
}

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
	if !config.tolerant || config.profile {
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
