// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_reporting.go; SHA-256 18a5ba93fa7bbd62b4dff925de9646190c5a4e92bf6edc820c960c9c5eb5564c.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"unicode/utf8"
	"weak"
)

// X.690 (02/2021) §§8.23.3–8.23.5, 8.23.10: report each invalid
// octet once, with offsets in the concatenated string. Resolve its element
// only on the finding path; a valid string needs no location or report state.
func reportStringOctets(number int, contents []byte, source *byte, logicalOffset int, config decodeConfig, options []DecodeOption, preflight bool, position *Violation, initial ...stringControlState) error {
	if position == nil {
		located, err := locateViolation(config, Violation{Path: qualifyConstraintPath(options, "")}, "")
		if err != nil {
			return err
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
	controls := stringControlState{}
	if len(initial) != 0 {
		controls = initial[0]
	}
	for offset := 0; offset < len(contents); {
		size := 1
		forbiddenControl := false
		noncharacter := false
		invalid := !alphabetOctet(number, contents[offset])
		if number == tag.TagUTF8String {
			var r rune
			r, size = utf8.DecodeRune(contents[offset:])
			forbiddenControl = controls.consume(number, r)
			noncharacter = isUnicodeNoncharacter(r)
			// ISO/IEC 10646:2003 §§7 a), 8 also exclude noncharacters.
			invalid = r == utf8.RuneError && size == 1 || noncharacter || forbiddenControl
		}
		if number == tag.TagIA5String {
			forbiddenControl = controls.consume(number, rune(contents[offset]))
			invalid = invalid || forbiddenControl
		}
		if invalid {
			location := logicalOffset + offset
			record := *position
			// Keep the existing string report metadata; only its physical
			// offset and structural path are enriched by location resolution.
			record.Source, record.ChildIndexes = "", nil
			record.Rule, record.Constraint = rule, constraint
			if noncharacter {
				record.Rule, record.Constraint = unicodeNoncharacterRule(), unicodeNoncharacterConstraint
			}
			if forbiddenControl {
				record.Constraint = stringControlConstraint(number)
				if number == tag.TagIA5String {
					record.Rule.Clause = "8.23.5.3"
				}
			}
			record.ObservedValue, record.OctetOffset = fmt.Sprintf("%02x", contents[offset]), &location
			record.source, record.preflight, record.scope = weak.Make(source), preflight, config.reportScope
			if err := config.violations.append(record, config.diagnostics); err != nil {
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
