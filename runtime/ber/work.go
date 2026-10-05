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
		if t.Class == tag.ClassUniversal && t.Number == 0 {
			return fmt.Errorf("%w: standalone BER end-of-contents", ErrInvalidTag)
		}
		// Checked before either length branch, so an indefinite length
		// cannot carry a constructed primitive-only type past it.
		if err := checkUniversalForm(t); err != nil {
			return err
		}
		if elements >= limits.MaxElements {
			return fmt.Errorf("%w: BER element limit exceeded", ErrInvalidValue)
		}
		elements++
		start := pos + tagLen + lenLen
		var contents []byte
		if !indefinite && length <= parent.end-start {
			contents = data[start : start+length]
		}
		markBERForm(config.form, t, data[pos+tagLen:start], indefinite, contents)
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

// checkUniversalForm rejects a universal type in the form X.690 (02/2021)
// forbids for it. BOOLEAN (§8.2.1), INTEGER (§8.3.1), ENUMERATED (§8.4),
// REAL (§8.5.1), NULL (§8.8.1), OBJECT IDENTIFIER (§8.19.1), RELATIVE-OID
// (§8.20.1), the OID and relative OID IRI types (§§8.21.1, 8.22.1) and TIME,
// DATE, TIME-OF-DAY, DATE-TIME and DURATION (§§8.26.1.1–8.26.5.1) are
// primitive. SEQUENCE and SEQUENCE OF (§§8.9.1, 8.10.1), SET and SET OF
// (§§8.11.1, 8.12.1), EMBEDDED PDV (§8.17.1), EXTERNAL (§8.18.1) and
// CHARACTER STRING (§8.24.1) are encoded as sequences, so constructed.
// validateDERUniversalValue applies the same forms.
func checkUniversalForm(t tag.Tag) error {
	if t.Class != tag.ClassUniversal {
		return nil
	}
	switch t.Number {
	case tag.TagBoolean, tag.TagInteger, tag.TagEnumerated, tag.TagReal,
		tag.TagNull, tag.TagObjectID, tag.TagRelativeOID, tag.TagOIDIRI,
		tag.TagRelativeOIDIRI, tag.TagTime, tag.TagDate, tag.TagTimeOfDay,
		tag.TagDateTime, tag.TagDuration:
		if t.Constructed {
			return fmt.Errorf("%w: X.690 (02/2021) requires primitive universal tag %d", ErrInvalidTag, t.Number)
		}
	case tag.TagSequence, tag.TagSet, tag.TagExternal, tag.TagEmbeddedPDV,
		tag.TagCharacterString:
		if !t.Constructed {
			return fmt.Errorf("%w: X.690 (02/2021) requires constructed universal tag %d", ErrInvalidTag, t.Number)
		}
	}
	return nil
}

// markBERForm records, on a decode that tracks BER forms, one element whose
// valid BER form the DER encoder would change. lengthOctets are the element's
// length octets; contents are its contents octets when the length is definite
// and within the input, else nil. The checks read only this element, so the
// whole-element scanner and every typed decoder share them.
func markBERForm(form *berFormState, t tag.Tag, lengthOctets []byte, indefinite bool, contents []byte) {
	if form == nil || form.preserve {
		return
	}
	// X.690 (02/2021) §§8.1.3, 10.1: BER permits indefinite and
	// nonminimal definite lengths; DER uses the shortest definite form.
	if indefinite || len(lengthOctets) > 1 &&
		(lengthOctets[1] == 0 || len(lengthOctets) == 2 && lengthOctets[1] < 0x80) {
		form.preserve = true
		return
	}
	if t.Class != tag.ClassUniversal {
		return
	}
	// X.690 (02/2021) §§8.2.1, 8.6.2, 8.7.3,
	// 10.2, 11.1–11.2: these BER values have a different DER form.
	switch t.Number {
	case tag.TagBitString, tag.TagOctetString, tag.TagObjectDesc,
		tag.TagUTF8String, tag.TagNumericString, tag.TagPrintableString,
		tag.TagT61String, tag.TagVideotexString, tag.TagIA5String,
		tag.TagGraphicString, tag.TagVisibleString, tag.TagGeneralString,
		tag.TagUniversalString, tag.TagBMPString:
		if t.Constructed {
			form.preserve = true
		}
	case tag.TagBoolean:
		if !t.Constructed && len(contents) == 1 && contents[0] != 0 && contents[0] != 0xff {
			form.preserve = true
		}
	case tag.TagUTCTime, tag.TagGeneralizedTime:
		// The decoded value keeps any X.680 (02/2021) §46.3/§47.3 lexical
		// form, so only the constructed form (X.690 (02/2021) §8.23.6) needs
		// the original element.
		if t.Constructed {
			form.preserve = true
		}
	case tag.TagReal:
		if !t.Constructed && contents != nil {
			if len(contents) != 0 && contents[0]&0xc0 == 0 {
				// X.690 (02/2021) §11.3.2: the decimal DER form is
				// identifiable from its spelling, before bigint conversion.
				// The typed decoder validates the numeric value separately.
				if !canonicalDecimalRealContents(contents) {
					form.preserve = true
				}
				break
			}
			if decoded, decodeErr := decodeRealContents(contents); decodeErr == nil {
				if canonical, encodeErr := EncodeRealValue(decoded); encodeErr != nil || !bytes.Equal(contents, canonical) {
					form.preserve = true
				}
			}
		}
	}
}
