// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/restricted_tolerance.go; SHA-256 c176783d2439dd40d8a7b4a9019cf9d3328e7677025a07765c226e85f3aef63a.
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

func checkAlphabetString(number int, contents []byte, source *byte, logicalOffset int, config decodeConfig, options []DecodeOption, preflight bool, position *Violation) error {
	if validAlphabetContents(number, contents) {
		return nil
	}
	if !config.tolerant {
		return fmt.Errorf("%w: %s", ErrInvalidValue, alphabetRule(number))
	}
	// Strict opaque refusal rescans need one finding, independent of the
	// tolerant report budget. The enclosing BER scan still checks all later
	// structure (X.690 (02/2021) §§8.1.1, 8.23.10).
	if config.firstUTF8Only {
		config.violations.mu.Lock()
		found := len(config.violations.records) != 0
		config.violations.mu.Unlock()
		if found {
			return nil
		}
	}
	if position == nil {
		var located Violation
		leaf := ""
		if config.location != nil {
			leaf = config.location.fieldName()
		}
		located.Path = qualifyConstraintPath(options, "")
		if leaf != "" && !config.location.fieldAlreadyApplied(options) {
			located.Path = joinUTF8Path(located.Path, leaf)
		}
		located, err := locateViolation(config, located, leaf)
		if err != nil {
			return err
		}
		if config.location != nil && len(config.location.rootInput()) != 0 {
			located.origin = weak.Make(&config.location.rootInput()[0])
		}
		position = &located
	}

	// Each out-of-alphabet octet has its own bounded report. Logical offsets
	// continue across OCTET STRING segments (X.690 (02/2021) §8.23.3).
	for offset := 0; offset < len(contents); {
		size := 1
		if !alphabetOctet(number, contents[offset]) {
			location := logicalOffset + offset
			record := *position
			record.Rule = alphabetRuleRef(number)
			record.Constraint = alphabetRule(number)
			record.ObservedValue, record.OctetOffset = fmt.Sprintf("%02x", contents[offset]), &location
			record.source, record.preflight, record.scope = weak.Make(source), preflight, config.reportScope
			if err := config.violations.append(record, config.diagnostics); err != nil {
				return err
			}
			if config.firstUTF8Only {
				return nil
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
