// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/string_reporting.go; SHA-256 7775d228c1289069becbad2cb9b35ca640a6fff4d4467e8f1068e2f968e3e213.
package ber

import (
	"fmt"
	"unicode/utf8"
	"weak"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §§8.23.3–8.23.5, 8.23.10: report each invalid
// octet once, with offsets in the concatenated string. Resolve its element
// only on the finding path; a valid string needs no location or report state.
func reportStringOctets(number int, contents []byte, source *byte, logicalOffset int, config decodeConfig, options []DecodeOption, preflight bool, position *Violation) error {
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

	rule, constraint := alphabetRuleRef(number), alphabetRule(number)
	if number == tag.TagUTF8String {
		rule = RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}
		constraint = "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)"
	}
	// DecodeRune consumes one octet on an invalid encoding. Never format
	// the remaining string: a bounded observation keeps total work linear.
	for offset := 0; offset < len(contents); {
		size := 1
		invalid := !alphabetOctet(number, contents[offset])
		if number == tag.TagUTF8String {
			var r rune
			r, size = utf8.DecodeRune(contents[offset:])
			invalid = r == utf8.RuneError && size == 1
		}
		if invalid {
			location := logicalOffset + offset
			record := *position
			record.Rule, record.Constraint = rule, constraint
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
