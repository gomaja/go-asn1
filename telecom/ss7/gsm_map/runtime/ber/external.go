// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/external.go; SHA-256 b25fba69471956dd42152e934bf7176c710ab028f277a24517bb4a2f46b21232.
package ber

import (
	"fmt"
	"math"
	"weak"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// DecodeExternal decodes X.690 (02/2021) §8.18.1's UNIVERSAL 8 sequence.
func DecodeExternal(data []byte, options ...DecodeOption) (runtime.External, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return runtime.External{}, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagExternal {
		return runtime.External{}, 0, fmt.Errorf("%w: expected constructed EXTERNAL, got %s", unexpectedElementError(data[:total], options), t)
	}
	if !t.Constructed {
		return runtime.External{}, 0, fmt.Errorf("%w: expected constructed EXTERNAL, got %s", ErrInvalidTag, t)
	}
	result, err := decodeExternalValue(value, data[:total], options...)
	if err != nil {
		return runtime.External{}, 0, err
	}
	if ReplayCaptureEnabled(options) {
		result.RememberBER(data[:total])
	}
	return result, total, nil
}

// DecodeExternalValue decodes the contents of an implicitly tagged EXTERNAL.
func DecodeExternalValue(value []byte, options ...DecodeOption) (runtime.External, error) {
	return decodeExternalValue(value, nil, options...)
}

func decodeExternalValue(value, element []byte, options ...DecodeOption) (runtime.External, error) {
	if err := ValidateDecodeOptions(options...); err != nil {
		return runtime.External{}, err
	}
	var result runtime.External
	offset := 0
	if offset < len(value) {
		t, _, _, err := DecodeTLV(value[offset:], options...)
		if err != nil {
			return result, err
		}
		if t.Class == tag.ClassUniversal && t.Number == tag.TagObjectID {
			MarkPreflightTarget(options, "direct-reference", value[offset:])
			oid, n, err := DecodeObjectIdentifier(value[offset:], options...)
			if err != nil {
				return result, err
			}
			result.DirectReference = oid
			if n <= 0 || n > len(value)-offset {
				return result, ErrInvalidLength
			}
			offset += n
		}
	}
	if offset < len(value) {
		t, _, _, err := DecodeTLV(value[offset:], options...)
		if err != nil {
			return result, err
		}
		if t.Class == tag.ClassUniversal && t.Number == tag.TagInteger {
			MarkPreflightTarget(options, "indirect-reference", value[offset:])
			integer, n, err := DecodeBigInt(value[offset:], options...)
			if err != nil {
				return result, err
			}
			result.IndirectReference = integer
			if n <= 0 || n > len(value)-offset {
				return result, ErrInvalidLength
			}
			offset += n
		}
	}
	if offset < len(value) {
		t, _, _, err := DecodeTLV(value[offset:], options...)
		if err != nil {
			return result, err
		}
		if t.Class == tag.ClassUniversal && t.Number == tag.TagObjectDesc {
			MarkPreflightTarget(options, "data-value-descriptor", value[offset:])
			descriptor, n, err := DecodeString(value[offset:], tag.TagObjectDesc, options...)
			if err != nil {
				return result, err
			}
			result.DataValueDescriptor = &descriptor
			if n <= 0 || n > len(value)-offset {
				return result, ErrInvalidLength
			}
			offset += n
		}
	}
	// X.690 (02/2021) §8.18.4 Table 2 and X.680 (02/2021) §37.5:
	// every permitted EXTERNAL identification has a direct or indirect reference.
	if result.DirectReference.IsZero() && result.IndirectReference == nil {
		return result, fmt.Errorf("%w: EXTERNAL identification requires a direct or indirect reference", ErrInvalidValue)
	}
	if offset >= len(value) {
		return result, fmt.Errorf("%w: EXTERNAL encoding choice is absent", ErrUnexpectedElement)
	}
	MarkPreflightTarget(options, "encoding", value[offset:])
	t, n, choice, err := DecodeTLV(value[offset:], options...)
	if err != nil {
		return result, err
	}
	if n <= 0 || n > len(value)-offset {
		return result, ErrInvalidLength
	}
	if offset+n != len(value) {
		// X.690 (02/2021) §§8.1.2, 8.18.1: only a complete extra
		// component is an abstract-syntax mismatch. Parse any tail before
		// classifying it so a malformed identifier or length keeps its BER
		// diagnostic.
		if err := validateExtraElements(value[offset:], options); err != nil {
			return result, err
		}
		return result, ErrUnexpectedElement
	}
	if t.Class != tag.ClassContextSpecific {
		return result, fmt.Errorf("%w: EXTERNAL encoding choice has tag %s", unexpectedElementError(value[offset:], options), t)
	}
	switch t.Number {
	case 0:
		if !t.Constructed {
			return result, fmt.Errorf("%w: single-ASN1-type must be explicit", ErrInvalidTag)
		}
		// X.690 (02/2021) §§8.14.3, 8.18.1: a complete empty
		// wrapper lacks its mandatory value; it is not truncated octets.
		if len(choice) == 0 {
			return result, ErrUnexpectedElement
		}
		innerTag, innerLen, _, err := DecodeTLV(choice, options...)
		if err != nil {
			return result, err
		}
		if innerLen != len(choice) {
			// X.690 (02/2021) §§8.1.2–8.1.3: malformed tail octets
			// retain their encoding error before an extra value is classified.
			if err := validateExtraElements(choice, options); err != nil {
				return result, err
			}
			return result, ErrUnexpectedElement
		}
		// X.690 (02/2021) §§8.9.2, 8.18.1, 8.18.9 require complete
		// encodings throughout the open value. The validator reuses an
		// unchanged generated context's validated-element proof. Scan the
		// enclosing element when available so tolerant UTF-8 reports
		// (§8.23.10), as well as errors, have whole-element coordinates.
		scan := choice
		if element != nil {
			scan = element
		}
		index := 0
		if element == nil {
			if !result.DirectReference.IsZero() {
				index++
			}
			if result.IndirectReference != nil {
				index++
			}
			if result.DataValueDescriptor != nil {
				index++
			}
		}
		if err := validateExternalSingleASN1(scan, value, index, element == nil, options); err != nil {
			if element != nil {
				return result, err
			}
			err = externalStructureError(err, value, choice, []int{index, 0}, options)
			return result, err
		}
		result.Encoding = runtime.ExternalSingleASN1Type
		// X.690 (02/2021) §§8.1.2.1, 8.1.2.5, 8.18.6: identify the inner value.
		result.SingleASN1Type = runtime.RawValue{Class: int(innerTag.Class), Tag: innerTag.Number, Constructed: innerTag.Constructed, Bytes: append([]byte(nil), choice...)}
	case 1:
		octets, err := DecodeImplicitOctetStringValue(t.Constructed, choice, options...)
		if err != nil {
			return result, err
		}
		result.Encoding = runtime.ExternalOctetAligned
		result.OctetAligned = append([]byte(nil), octets...)
	case 2:
		bits, unused, err := DecodeImplicitBitStringValue(t.Constructed, choice, options...)
		if err != nil {
			return result, err
		}
		result.Encoding = runtime.ExternalArbitrary
		bitLength, err := externalBitLength(len(bits), unused)
		if err != nil {
			return result, err
		}
		result.Arbitrary = runtime.BitString{Bytes: append([]byte(nil), bits...), BitLength: bitLength}
	default:
		return result, fmt.Errorf("%w: EXTERNAL encoding choice %d", unexpectedElementError(value[offset:], options), t.Number)
	}
	return result, nil
}

// An implicit EXTERNAL has no outer identifier to scan. Stage its open-value
// reports locally so physical positions can be qualified before publication,
// retaining the same X.690 (02/2021) §8.23.10 diagnostics as a full EXTERNAL.
func validateExternalSingleASN1(scan, value []byte, index int, implicit bool, options []DecodeOption) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	// TS 29.002 V19.1.0 §17.1.1 covers MAP-defined syntax only.
	// This X.690 (02/2021) §8.18.9 scan cannot claim protocol ownership.
	// Keep the caller's marker intact, and retain its proof and locations.
	if config.form != nil && config.form.mapProfile() {
		form := *config.form
		form.mapSyntax = mapSyntaxGeneric
		form.mapPending = nil
		config.form = &form
	}
	if !implicit || !config.tolerant || config.location != nil {
		return validateBERElement(scan, options, config)
	}
	base, ok := berSubsliceOffset(value, scan)
	if !ok {
		return ErrInvalidLength
	}
	var pending ViolationLog
	local := config
	local.reportScope = new(reportScope)
	pending.scope = local.reportScope
	local.violations = &pending
	err = validateBERElement(scan, options, local)
	for _, record := range pending.records {
		if record.Offset == nil || *record.Offset < 0 || *record.Offset > len(value)-base {
			return ErrInvalidLength
		}
		relativeOffset, relativeIndexes := *record.Offset, record.ChildIndexes
		offset := base + *record.Offset
		record.Offset = &offset
		record.ChildIndexes = append([]int{index, 0}, record.ChildIndexes...)
		record.Path = qualifyConstraintPath(options, "")
		for _, child := range record.ChildIndexes {
			record.Path = joinUTF8Path(record.Path, fmt.Sprintf("child[%d]", child))
		}
		record.origin = weak.Make(&value[0])
		record.scope = config.reportScope
		if reportErr := config.violations.append(record, config.diagnostics); reportErr != nil {
			return &ElementError{offset: relativeOffset, childIndexes: relativeIndexes, cause: reportErr}
		}
	}
	return err
}

// externalStructureError translates a standalone open-value scan into its
// enclosing input. Generated locations already refer to the public root.
func externalStructureError(err error, input, child []byte, indexes []int, options []DecodeOption) error {
	located, ok := err.(*ElementError)
	config, optionErr := decodeOptions(options)
	if !ok || optionErr != nil || config.location != nil {
		return err
	}
	offset, ok := berSubsliceOffset(input, child)
	if !ok || located.offset < 0 || located.offset > len(input)-offset {
		return err
	}
	return &ElementError{offset: offset + located.offset, childIndexes: append(indexes, located.childIndexes...), cause: located.cause}
}

// EncodeExternal writes a typed EXTERNAL value using BER (X.690 (02/2021)
// §8.18.1). WithoutBERReplay rebuilds typed alternatives and copies an opaque
// single-ASN1-type value only if it passes the DER checks (§8.18.9).
func EncodeExternal(value runtime.External, options ...EncodeOption) ([]byte, error) {
	return encodeExternal(value, false, options...)
}

// EncodeExternalDER writes a typed EXTERNAL value using DER (X.690 §§10–11).
func EncodeExternalDER(value runtime.External) ([]byte, error) { return encodeExternal(value, true) }

func encodeExternal(value runtime.External, der bool, options ...EncodeOption) ([]byte, error) {
	if _, err := encodeOptions(options); err != nil {
		return nil, err
	}
	// Check before returning preserved BER too, so a changed value cannot evade
	// the required identification (X.690 §8.18.4 Table 2; X.680 §37.5).
	if value.DirectReference.IsZero() && value.IndirectReference == nil {
		return nil, fmt.Errorf("%w: EXTERNAL identification requires a direct or indirect reference", ErrInvalidValue)
	}
	if value.Encoding == runtime.ExternalSingleASN1Type {
		if err := ValidateRawValueIdentifier(value.SingleASN1Type); err != nil {
			return nil, err
		}
		if !der {
			// X.690 (02/2021) §§8.18.1, 8.23.10: validate the
			// retained open value before the unchanged EXTERNAL shortcut.
			if err := CheckBEROpaqueElement(value.SingleASN1Type.Bytes, options...); err != nil {
				return nil, err
			}
		}
	}
	if !der {
		if original := replayExternalForm(value, options); original != nil {
			return original, nil
		}
	}
	var children []byte
	if !value.DirectReference.IsZero() {
		oid, err := EncodeObjectIdentifierChecked(value.DirectReference)
		if err != nil {
			return nil, err
		}
		children = append(children, oid...)
	}
	if value.IndirectReference != nil {
		integer, err := EncodeBigInt(value.IndirectReference)
		if err != nil {
			return nil, err
		}
		children = append(children, integer...)
	}
	if value.DataValueDescriptor != nil {
		descriptor, err := EncodeStringTagChecked(tag.TagObjectDesc, *value.DataValueDescriptor)
		if err != nil {
			return nil, err
		}
		children = append(children, descriptor...)
	}
	switch value.Encoding {
	case runtime.ExternalSingleASN1Type:
		inner := value.SingleASN1Type.Bytes
		if der {
			if err := ValidateDEREncodedElement(inner); err != nil {
				return nil, err
			}
		}
		encoded, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 0, Constructed: true}, inner)
		if err != nil {
			return nil, err
		}
		children = append(children, encoded...)
	case runtime.ExternalOctetAligned:
		encoded, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, value.OctetAligned)
		if err != nil {
			return nil, err
		}
		children = append(children, encoded...)
	case runtime.ExternalArbitrary:
		{
			bits := value.Arbitrary
			if bits.BitLength < 0 {
				return nil, fmt.Errorf("%w: EXTERNAL arbitrary bit length", ErrInvalidValue)
			}
			expectedOctets := bits.BitLength / 8
			unused := 0
			if rem := bits.BitLength % 8; rem != 0 {
				if expectedOctets >= math.MaxInt {
					return nil, fmt.Errorf("%w: EXTERNAL arbitrary bit length", ErrInvalidValue)
				}
				expectedOctets++
				unused = 8 - rem
			}
			if unused < 0 || unused > 7 || unused > 0 && len(bits.Bytes) == 0 {
				return nil, fmt.Errorf("%w: EXTERNAL arbitrary unused-bit count", ErrInvalidValue)
			}
			if len(bits.Bytes) != expectedOctets {
				return nil, fmt.Errorf("%w: EXTERNAL arbitrary bit length", ErrInvalidValue)
			}
			bitValue, err := EncodeBitStringValue(bits.Bytes, unused)
			if err != nil {
				return nil, err
			}
			encoded, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, bitValue)
			if err != nil {
				return nil, err
			}
			children = append(children, encoded...)
		}
	default:
		return nil, fmt.Errorf("%w: EXTERNAL encoding choice %d", ErrInvalidValue, value.Encoding)
	}
	encoded, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagExternal, Constructed: true}, children)
	if err != nil {
		return nil, err
	}
	if der {
		if err := ValidateDEREncodedElement(encoded); err != nil {
			return nil, err
		}
	}
	if !der {
		encoded = replayExternalEditedParts(value, encoded, options)
	}
	return encoded, nil
}

// X.690 (02/2021) §8.6 represents a BIT STRING with an unused-bit count.
// The public BitString length uses int, so reject wire lengths beyond it.
func externalBitLength(octets, unused int) (int, error) {
	return BitStringBitLength(octets, unused)
}
