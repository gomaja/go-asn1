// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8.go; SHA-256 7f4ce4e38ff85270019c8746d9e10cf19d6467b0e77627ea6fa41ada547ca3f4.
package ber

import (
	"fmt"
	"unicode/utf8"

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
	return reportStringOctets(tag.TagUTF8String, contents, source, 0, config, options, preflight, position)
}

func decodeStringValueTagOptions(tagNum int, contents []byte, source *byte, options []DecodeOption) (string, error) {
	if isAlphabetString(tagNum) {
		if len(options) == 1 {
			if context, ok := options[0].(*generatedDecodeOption); ok && context != nil && context.source != nil {
				if form := context.config.form; form != nil && form.mapPending != nil && form.mapPending.contents != nil {
					claimGeneratedAlphabet(context.config, options)
				}
				return string(contents), nil
			}
		}
		// X.680 (02/2021) §41, §51.7: the generated check intersects the
		// repertoire and FROM constraint once, retaining its typed diagnostic.
		config, err := decodeOptions(options)
		if err != nil {
			return "", err
		}
		if generatedContentsPosition(config, options) {
			claimGeneratedAlphabet(config, options)
			return string(contents), nil
		}
		if err := checkAlphabetString(tagNum, contents, source, 0, config, options, false, nil); err != nil {
			return "", err
		}
		return string(contents), nil
	}

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
