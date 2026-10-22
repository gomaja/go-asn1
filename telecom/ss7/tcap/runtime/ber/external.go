// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/external.go; SHA-256 57d3c12a3ac8f97639a350bdb25317ed4e4d4b44d9187ec692561700aa87d377.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
)

// DecodeExternal decodes X.690 (02/2021) §8.18.1's UNIVERSAL 8 sequence.
func DecodeExternal(data []byte, options ...DecodeOption) (runtime.External, int, error) {
	return decodeExternal(data, options, false)
}

func decodeExternal(data []byte, options []DecodeOption, preflight bool) (runtime.External, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return runtime.External{}, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagExternal || !t.Constructed {
		return runtime.External{}, 0, fmt.Errorf("%w: expected constructed EXTERNAL, got %s", ErrInvalidTag, t)
	}
	result, err := decodeExternalValue(value, data[:total], options, preflight)
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
	return decodeExternalValue(value, nil, options, false)
}

func decodeExternalValue(value, element []byte, options []DecodeOption, preflight bool) (runtime.External, error) {
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
		return result, fmt.Errorf("%w: EXTERNAL encoding choice is absent", ErrInvalidValue)
	}
	t, n, choice, err := DecodeTLV(value[offset:], options...)
	if err != nil {
		return result, err
	}
	if n <= 0 || n > len(value)-offset {
		return result, ErrInvalidLength
	}
	if offset+n != len(value) {
		return result, ErrExtraData
	}
	if t.Class != tag.ClassContextSpecific {
		return result, fmt.Errorf("%w: EXTERNAL encoding choice has tag %s", ErrInvalidTag, t)
	}
	switch t.Number {
	case 0:
		if !t.Constructed {
			return result, fmt.Errorf("%w: single-ASN1-type must be explicit", ErrInvalidTag)
		}
		innerTag, innerLen, _, err := DecodeTLV(choice, options...)
		if err != nil {
			return result, err
		}
		if innerLen != len(choice) {
			return result, ErrExtraData
		}
		if !preflight {
			// X.690 (02/2021) §§8.9.2, 8.18.1, 8.18.9 require complete
			// encodings throughout the open value. The validator reuses an
			// unchanged generated context's validated-element proof. Scan the
			// enclosing element when available so tolerant UTF-8 reports
			// (§8.23.10), as well as errors, have whole-element coordinates.
			scan := choice
			if element != nil {
				scan = element
			}
			config, err := decodeOptions(options)
			if err != nil {
				return result, err
			}
			// Q.773 (06/1997) §4.1.1 governs its own abstract syntaxes.
			// This scan checks X.690 (02/2021) §8.18.9 only; the generated
			// root and typed dialogue decoder retain protocol ownership.
			// Keep options intact for validated-element proofs and locations.
			config.profile, config.profileEncode, config.profileNested = false, false, false
			config.profileType, config.profileSource = "", ""
			if err := validateBERElement(scan, options, config); err != nil {
				if element != nil {
					return result, err
				}
				index := 0
				if !result.DirectReference.IsZero() {
					index++
				}
				if result.IndirectReference != nil {
					index++
				}
				if result.DataValueDescriptor != nil {
					index++
				}
				err = externalStructureError(err, value, choice, []int{index, 0}, options)
				return result, err
			}
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
		return result, fmt.Errorf("%w: EXTERNAL encoding choice %d", ErrInvalidTag, t.Number)
	}
	return result, nil
}

// Only a generated call's private context or ownership state can use
// PrepareGeneratedBERInput's proof. Caller-made options get one full scan.
func prepareGeneratedExternalInput(data []byte, options []DecodeOption) ([]byte, []DecodeOption, error) {
	for _, option := range options {
		if context, ok := option.(*generatedDecodeOption); ok && context != nil {
			return PrepareGeneratedBERInput(data, options)
		}
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.generated {
			return PrepareGeneratedBERInput(data, options)
		}
	}
	if err := ValidateBERElement(data, options...); err != nil {
		return nil, nil, err
	}
	return data, options, nil
}

// DecodeGeneratedExternal is for generated code only. It prepares and validates
// a complete element, then decodes its EXTERNAL before returning. Tagging is
// "", "EXPLICIT", or "IMPLICIT". The prepared input and options are returned
// for the generated decoder's remaining tag checks, locations and replay.
//
// X.690 (02/2021) §§8.1, 8.18 and 8.23.10: PrepareGeneratedBERInput traverses
// every constructed child, including a single-ASN1-type open value, in light
// and adaptive modes; proof mode checks its immutable copy and boundaries.
// The skip is a private argument used only below, immediately after that
// validation in this same call. No option, received address, detached context
// or caller-made marker can claim it. Callers must not mutate input during
// decoding, as required by PrepareGeneratedBERInput.
func DecodeGeneratedExternal(data []byte, options []DecodeOption, tagging string) (runtime.External, []byte, []DecodeOption, error) {
	if tagging != "" && tagging != "EXPLICIT" && tagging != "IMPLICIT" {
		return runtime.External{}, nil, nil, fmt.Errorf("%w: invalid generated EXTERNAL tagging", ErrInvalidValue)
	}
	prepared, context, err := prepareGeneratedExternalInput(data, options)
	if err != nil {
		return runtime.External{}, nil, nil, err
	}
	input := prepared
	if tagging != "" {
		t, n, value, err := DecodeTLV(input, context...)
		if err != nil {
			return runtime.External{}, prepared, context, err
		}
		if n != len(input) {
			return runtime.External{}, prepared, context, ErrExtraData
		}
		if !t.Constructed {
			return runtime.External{}, prepared, context, ErrInvalidTag
		}
		if tagging == "IMPLICIT" {
			result, err := decodeExternalValue(value, input, context, true)
			return result, prepared, context, err
		}
		input = value
	}
	result, n, err := decodeExternal(input, context, true)
	if err == nil && n != len(input) {
		err = ErrExtraData
	}
	return result, prepared, context, err
}

// DecodeGeneratedExternalSequence is for generated code only. It prepares a
// complete SEQUENCE containing untagged EXTERNAL children, then
// decodes those children in this call. On a child error it returns the decoded
// prefix so generated code can retain its element path and envelope location.
// Its validation evidence has the same
// scope as DecodeGeneratedExternal; it never issues a reusable bypass option.
func DecodeGeneratedExternalSequence(data []byte, options []DecodeOption) ([]runtime.External, []byte, []DecodeOption, error) {
	prepared, context, err := prepareGeneratedExternalInput(data, options)
	if err != nil {
		return nil, nil, nil, err
	}
	t, total, content, err := DecodeTLV(prepared, context...)
	if err != nil {
		return nil, prepared, context, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagSequence || !t.Constructed {
		return nil, prepared, context, ErrInvalidTag
	}
	if total != len(prepared) {
		return nil, prepared, context, ErrExtraData
	}
	var proof *validatedBERSource
	if len(context) != 0 {
		if generated, ok := context[0].(*generatedDecodeOption); ok && generated != nil && generated.source != nil && !generated.source.light {
			proof = generated.source
		}
	}
	var result []runtime.External
	for offset := 0; offset < len(content); {
		MarkPreflightElement(context, len(result), content[offset:])
		// Proof mode can bound the child from its authenticated element table.
		// DecodeTLV still compares that child's bytes with the immutable copy.
		// Light mode needs only its ordinary prefix decode. Do not delimit an
		// indefinite child twice, or compare every remaining sibling per child.
		child := content[offset:]
		if proof != nil {
			if start, within := berSubsliceOffset(proof.owned, child); within {
				if end, found := proof.spanEnd(start); found && end >= start {
					size := end - start
					if size <= len(child) {
						child = child[:size]
					}
				}
			}
		}
		external, n, err := decodeExternal(child, context, true)
		if err != nil {
			return result, prepared, context, err
		}
		if n <= 0 || n > len(content)-offset {
			return result, prepared, context, ErrInvalidLength
		}
		result = append(result, external)
		offset += n
	}
	return result, prepared, context, nil
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
// §8.18.1). WithoutBERReplay rebuilds typed alternatives and refuses the
// opaque single-ASN1-type alternative (§8.18.9). Default replay is unchanged.
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
		if err := CheckBEROpaqueReplay(options...); err != nil {
			return nil, err
		}
		inner := value.SingleASN1Type.Bytes
		if err := ValidateBERElement(inner, encodingStructureOption(inner)); err != nil {
			return nil, err
		}
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
