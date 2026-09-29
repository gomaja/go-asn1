package ber

import (
	"fmt"
	"math"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// DecodeExternal decodes X.690 (02/2021) §8.18.1's UNIVERSAL 8 sequence.
func DecodeExternal(data []byte, options ...DecodeOption) (runtime.External, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return runtime.External{}, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagExternal || !t.Constructed {
		return runtime.External{}, 0, fmt.Errorf("%w: expected constructed EXTERNAL, got %s", ErrInvalidTag, t)
	}
	result, err := DecodeExternalValue(value, options...)
	if err != nil {
		return runtime.External{}, 0, err
	}
	result.RememberBER(data[:total])
	return result, total, nil
}

// DecodeExternalValue decodes the contents of an implicitly tagged EXTERNAL.
func DecodeExternalValue(value []byte, options ...DecodeOption) (runtime.External, error) {
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
			result.DirectReference = runtime.ObjectIdentifier(oid)
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
	if result.DirectReference == nil && result.IndirectReference == nil {
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
		_, innerLen, _, err := DecodeTLV(choice, options...)
		if err != nil {
			return result, err
		}
		if innerLen != len(choice) {
			return result, ErrExtraData
		}
		result.Encoding = runtime.ExternalSingleASN1Type
		result.SingleASN1Type = runtime.RawValue{Bytes: append([]byte(nil), choice...)}
	case 1:
		reconstructed, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagOctetString, Constructed: t.Constructed}, choice)
		if err != nil {
			return result, err
		}
		octets, _, err := DecodeOctetString(reconstructed, options...)
		if err != nil {
			return result, err
		}
		result.Encoding = runtime.ExternalOctetAligned
		result.OctetAligned = append([]byte(nil), octets...)
	case 2:
		reconstructed, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString, Constructed: t.Constructed}, choice)
		if err != nil {
			return result, err
		}
		bits, unused, _, err := DecodeBitString(reconstructed, options...)
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

// EncodeExternal writes a typed EXTERNAL value using BER (X.690 §8.18.1).
func EncodeExternal(value runtime.External) ([]byte, error) { return encodeExternal(value, false) }

// EncodeExternalDER writes a typed EXTERNAL value using DER (X.690 §§10–11).
func EncodeExternalDER(value runtime.External) ([]byte, error) { return encodeExternal(value, true) }

func encodeExternal(value runtime.External, der bool) ([]byte, error) {
	// Check before returning preserved BER too, so a changed value cannot evade
	// the required identification (X.690 §8.18.4 Table 2; X.680 §37.5).
	if value.DirectReference == nil && value.IndirectReference == nil {
		return nil, fmt.Errorf("%w: EXTERNAL identification requires a direct or indirect reference", ErrInvalidValue)
	}
	if !der {
		if original := value.UnchangedBER(); original != nil {
			return original, nil
		}
	}
	var children []byte
	if value.DirectReference != nil {
		oid, err := EncodeObjectIdentifierChecked([]uint64(value.DirectReference))
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
			if unused > 0 && bits.Bytes[len(bits.Bytes)-1]&byte((1<<unused)-1) != 0 {
				return nil, fmt.Errorf("%w: nonzero unused EXTERNAL bits", ErrInvalidValue)
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
	return encoded, nil
}

// X.690 (02/2021) §8.6 represents a BIT STRING with an unused-bit count.
// The public BitString length uses int, so reject wire lengths beyond it.
func externalBitLength(octets, unused int) (int, error) {
	return BitStringBitLength(octets, unused)
}
