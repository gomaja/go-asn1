// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8.go; SHA-256 d4f96047a734a5fca2bf2bb7c5af1f71d54efbc3769deab4427ce1df3055755b.
package ber

import (
	"fmt"
	"unicode/utf8"
	"weak"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §8.23.10 and ISO/IEC 10646 Annex D require
// shortest-form UTF-8 scalar text, including for implicit string values.
func checkDecodedUTF8String(contents []byte, source *byte, options []DecodeOption) error {
	if utf8.Valid(contents) {
		return nil
	}
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	return checkUTF8String(contents, source, config, options, false, nil)
}

func checkUTF8String(contents []byte, source *byte, config decodeConfig, options []DecodeOption, preflight bool, position *Violation) error {
	if utf8.Valid(contents) {
		return nil
	}
	if !config.tolerant {
		return fmt.Errorf("%w: UTF8String is not shortest-form UTF-8 scalar text", ErrInvalidValue)
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
	var located Violation
	if position != nil {
		located = *position
	} else {
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
		if config.location != nil && len(config.location.origin.root) != 0 {
			located.origin = weak.Make(&config.location.origin.root[0])
		}
		position = &located
	}

	// DecodeRune consumes one octet on an invalid encoding. Report each such
	// octet separately, so equal bad octets at different locations stay distinct.
	// Never format the entire remaining string for each report: that is quadratic.
	for offset := 0; offset < len(contents); {
		r, size := utf8.DecodeRune(contents[offset:])
		if r == utf8.RuneError && size == 1 {
			location := offset
			record := *position
			record.Rule = RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}
			record.Constraint = "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)"
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

func decodeStringValueTagOptions(tagNum int, contents []byte, source *byte, options []DecodeOption) (string, error) {
	if tagNum == tag.TagUTF8String {
		if err := checkDecodedUTF8String(contents, source, options); err != nil {
			return "", err
		}
		// Converting bytes directly keeps tolerated octets; ranging over runes
		// would replace malformed sequences and destroy unchanged-value replay.
		return string(contents), nil
	}
	return DecodeStringValueTag(tagNum, contents)
}
