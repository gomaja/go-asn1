// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/utf8.go; SHA-256 a1ca3f4da5beb3bc25662afa526455ee99df5954a09185e133fa4b8ed2c67c94.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"unicode/utf8"
	"weak"
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
	return checkUTF8String(contents, source, config, options, false)
}

func checkUTF8String(contents []byte, source *byte, config decodeConfig, options []DecodeOption, preflight bool) error {
	if utf8.Valid(contents) {
		return nil
	}
	if !config.tolerant || config.profile {
		return fmt.Errorf("%w: UTF8String is not shortest-form UTF-8 scalar text", ErrInvalidValue)
	}
	path := qualifyConstraintPath(options, "")
	// DecodeRune consumes one octet on an invalid encoding. Report each such
	// octet separately, so equal bad octets at different locations stay distinct.
	// Never format the entire remaining string for each report: that is quadratic.
	for offset := 0; offset < len(contents); {
		r, size := utf8.DecodeRune(contents[offset:])
		if r == utf8.RuneError && size == 1 {
			location := offset
			if err := config.violations.append(Violation{
				Path: path, Constraint: "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)",
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
