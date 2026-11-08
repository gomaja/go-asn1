// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/utf8.go; SHA-256 55710231cc41cef7d51dc6e0f1ac4e9e36750e19af768b753b31a33b09a95819.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
)

// X.690 (02/2021) §8.23.10 and ISO/IEC 10646 Annex D require
// shortest-form UTF-8 scalar text, including for implicit string values.
func checkDecodedUTF8String(contents []byte, source *byte, options []DecodeOption) error {
	if validUTF8Contents(contents) {
		return nil
	}
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	return checkUTF8String(contents, source, config, options, false, nil)
}

func checkUTF8String(contents []byte, source *byte, config decodeConfig, options []DecodeOption, preflight bool, position *Violation) error {
	if validUTF8Contents(contents) {
		return nil
	}
	if !config.tolerant || config.profile {
		if !validStringControls(tag.TagUTF8String, string(contents)) {
			return invalidStringControl(tag.TagUTF8String)
		}
		return fmt.Errorf("%w: UTF8String violates its encoding or repertoire rules", ErrInvalidValue)
	}
	return reportStringOctets(tag.TagUTF8String, contents, source, 0, config, options, preflight, position)
}

func decodeStringValueTagOptions(tagNum int, contents []byte, source *byte, options []DecodeOption) (string, error) {
	if isAlphabetString(tagNum) && !validAlphabetContents(tagNum, contents) {
		config, err := decodeOptions(options)
		if err != nil {
			return "", err
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
