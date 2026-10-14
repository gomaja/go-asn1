package ber

import (
	"fmt"
	"unicode/utf8"
	"weak"

	"github.com/gomaja/go-asn1/runtime/tag"
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
	if !config.tolerant {
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
			if err := config.violations.append(ConstraintViolation{
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
