package ber

import (
	"bytes"
	"fmt"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// ValidateBERElement checks one complete BER TLV with a single linear scan.
// X.690 (02/2021) §§8.1.3 and 8.7 permit indefinite constructed values;
// the limits are operational safeguards, not restrictions in X.690.
func ValidateBERElement(data []byte, options ...DecodeOption) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	limits := config.limits
	if len(data) == 0 {
		return ErrTruncated
	}
	if len(data) > limits.MaxWork {
		return fmt.Errorf("%w: BER total-work limit exceeded", ErrInvalidValue)
	}
	type frame struct {
		end        int
		indefinite bool
	}
	stack := []frame{{end: len(data)}}
	pos, elements := 0, 0
	for len(stack) != 0 {
		parent := stack[len(stack)-1]
		if pos == parent.end {
			if parent.indefinite {
				return ErrTruncated
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if pos < 0 || pos > parent.end {
			return ErrInvalidLength
		}
		if len(stack) == 1 && elements > 0 {
			return ErrExtraData
		}
		if parent.indefinite && parent.end-pos >= 2 && data[pos] == 0 && data[pos+1] == 0 {
			pos += 2
			stack = stack[:len(stack)-1]
			continue
		}
		t, tagLen, err := DecodeTag(data[pos:parent.end])
		if err != nil {
			return err
		}
		if tagLen < 0 || tagLen > parent.end-pos {
			return ErrInvalidLength
		}
		length, indefinite, lenLen, err := DecodeLength(data[pos+tagLen : parent.end])
		if err != nil {
			return err
		}
		if lenLen < 0 || lenLen > parent.end-pos-tagLen {
			return ErrInvalidLength
		}
		// X.690 (02/2021) §§8.1.3, 10.1: BER permits indefinite and
		// nonminimal definite lengths; DER uses the shortest definite form.
		if config.form != nil && (indefinite || lenLen > 1 &&
			(length < 128 || data[pos+tagLen+1] == 0)) {
			config.form.preserve = true
		}
		if t.Class == tag.ClassUniversal && t.Number == 0 {
			return fmt.Errorf("%w: standalone BER end-of-contents", ErrInvalidTag)
		}
		if elements >= limits.MaxElements {
			return fmt.Errorf("%w: BER element limit exceeded", ErrInvalidValue)
		}
		elements++
		start := pos + tagLen + lenLen
		if config.form != nil && t.Class == tag.ClassUniversal {
			value := data[start:parent.end]
			// X.690 (02/2021) §§8.2.1, 8.6.2, 8.7.3,
			// 10.2, 11.1–11.2: these BER values have a different DER form.
			switch t.Number {
			case tag.TagBitString, tag.TagOctetString, tag.TagObjectDesc,
				tag.TagUTF8String, tag.TagNumericString, tag.TagPrintableString,
				tag.TagT61String, tag.TagVideotexString, tag.TagIA5String,
				tag.TagGraphicString, tag.TagVisibleString, tag.TagGeneralString,
				tag.TagUniversalString, tag.TagBMPString:
				if t.Constructed {
					config.form.preserve = true
				}
			case tag.TagBoolean:
				if !t.Constructed && !indefinite && length == 1 &&
					len(value) != 0 && value[0] != 0 && value[0] != 0xff {
					config.form.preserve = true
				}
			case tag.TagUTCTime, tag.TagGeneralizedTime:
				if t.Constructed {
					config.form.preserve = true
				} else if !indefinite && length <= len(value) {
					// X.690 (02/2021) §§11.7–11.8: only unusual forms
					// need the comparatively costly time parser.
					raw := string(value[:length])
					if t.Number == tag.TagUTCTime && (length != 13 || value[12] != 'Z') {
						if decoded, parseErr := parseUTCTime(raw); parseErr == nil && raw != decoded.UTC().Format("060102150405Z") {
							config.form.preserve = true
						}
					} else if t.Number == tag.TagGeneralizedTime && (length != 15 || value[14] != 'Z') {
						if decoded, parseErr := parseGeneralizedTime(raw); parseErr == nil && raw != decoded.UTC().Format("20060102150405.999999999Z") {
							config.form.preserve = true
						}
					}
				}
			case tag.TagReal:
				if !t.Constructed && !indefinite && length <= len(value) {
					if decoded, decodeErr := decodeRealContents(value[:length]); decodeErr == nil {
						if canonical, encodeErr := EncodeRealValue(decoded); encodeErr != nil || !bytes.Equal(value[:length], canonical) {
							config.form.preserve = true
						}
					}
				}
			}
		}
		if indefinite {
			if !t.Constructed {
				return ErrIndefiniteLength
			}
			if len(stack) > limits.MaxDepth {
				return fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
			}
			stack = append(stack, frame{end: parent.end, indefinite: true})
			pos = start
			continue
		}
		if start > parent.end {
			return ErrTruncated
		}
		if length > parent.end-start {
			return ErrTruncated
		}
		end := start + length
		if t.Class == tag.ClassUniversal && (t.Number == tag.TagInteger || t.Number == tag.TagEnumerated) {
			if t.Constructed {
				return fmt.Errorf("%w: X.690 (02/2021) §§8.3.1, 8.4 require primitive INTEGER and ENUMERATED", ErrInvalidTag)
			}
			if err := validateMinimalIntegerContents(data[start:end]); err != nil {
				return err
			}
		}
		if t.Constructed {
			if len(stack) > limits.MaxDepth {
				return fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
			}
			stack = append(stack, frame{end: end})
			pos = start
		} else {
			pos = end
		}
	}
	if pos != len(data) {
		return ErrExtraData
	}
	return nil
}
