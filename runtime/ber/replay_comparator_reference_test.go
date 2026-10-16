package ber

import (
	"bytes"
	"math"
	"math/big"
	"reflect"
	"strings"

	"github.com/gomaja/go-asn1/runtime"
)

// This reference keeps the comparator's pre-plan structure. CHOICE extension
// handling mirrors the production comparator so differential tests can compare
// root and per-node verdicts under the same generated layouts.
func compareBERValueNodesReference(left, right reflect.Value, depth int, nodeValues *replayNodeComparisons) berValueComparison {
	if !left.IsValid() || !right.IsValid() {
		return berComparison(left.IsValid() == right.IsValid())
	}
	if left.Type() != right.Type() || depth > 1024 {
		return berValueUnknown
	}
	if left.Type().ConvertibleTo(externalType) && left.CanAddr() && right.CanAddr() &&
		left.Addr().CanInterface() && right.Addr().CanInterface() &&
		left.Addr().CanConvert(externalPointerType) && right.Addr().CanConvert(externalPointerType) {
		// X.690 (02/2021) §8.18.1: the encoding CHOICE contributes only
		// its selected alternative to the EXTERNAL value.
		a := left.Addr().Convert(externalPointerType).Interface().(*runtime.External)
		b := right.Addr().Convert(externalPointerType).Interface().(*runtime.External)
		if a.Encoding != b.Encoding || a.DirectReference != b.DirectReference {
			return berValueDifferent
		}
		if (a.IndirectReference == nil) != (b.IndirectReference == nil) ||
			(a.DataValueDescriptor == nil) != (b.DataValueDescriptor == nil) {
			return berValueUnknown
		}
		if a.IndirectReference != nil && a.IndirectReference.Cmp(b.IndirectReference) != 0 {
			return berValueDifferent
		}
		if a.DataValueDescriptor != nil && *a.DataValueDescriptor != *b.DataValueDescriptor {
			return berValueDifferent
		}
		switch a.Encoding {
		case runtime.ExternalSingleASN1Type:
			if a.SingleASN1Type.Class == b.SingleASN1Type.Class &&
				a.SingleASN1Type.Tag == b.SingleASN1Type.Tag &&
				a.SingleASN1Type.Constructed == b.SingleASN1Type.Constructed &&
				bytes.Equal(a.SingleASN1Type.Bytes, b.SingleASN1Type.Bytes) {
				return berValueEqual
			}
			return berValueUnknown
		case runtime.ExternalOctetAligned:
			return berComparison(bytes.Equal(a.OctetAligned, b.OctetAligned))
		case runtime.ExternalArbitrary:
			return compareBERValueNodesReference(reflect.ValueOf(&a.Arbitrary).Elem(), reflect.ValueOf(&b.Arbitrary).Elem(), depth+1, nodeValues)
		default:
			return berValueUnknown
		}
	}
	if left.Type() == realType {
		if !left.CanInterface() || !right.CanInterface() {
			return berValueUnknown
		}
		a, b := left.Interface().(runtime.Real), right.Interface().(runtime.Real)
		if a.Validate() != nil || b.Validate() != nil {
			return berValueUnknown
		}
		// The base of a nonzero REAL is part of its abstract value:
		// X.690 (02/2021) §8.5.4 distinguishes base 2 from base 10.
		if a.Kind == runtime.RealFinite && a.Mantissa != nil && a.Base != b.Base {
			return berValueDifferent
		}
		// X.690 (02/2021) §§8.5.4–8.5.7 permit several binary
		// mantissa and exponent representations of one REAL value.
		comparison, err := compareReal(a, b)
		if err != nil {
			return berValueUnknown
		}
		return berComparison(comparison == 0)
	}
	if left.Type() == bigIntType {
		if !left.CanAddr() || !right.CanAddr() || !left.Addr().CanInterface() || !right.Addr().CanInterface() {
			return berValueUnknown
		}
		a, b := left.Addr().Interface().(*big.Int), right.Addr().Interface().(*big.Int)
		return berComparison(a.Cmp(b) == 0)
	}
	if left.Type() == bitStringType {
		if !left.CanInterface() || !right.CanInterface() {
			return berValueUnknown
		}
		a, b := left.Interface().(runtime.BitString), right.Interface().(runtime.BitString)
		if !berBitStringLengthFits(a) || !berBitStringLengthFits(b) || a.BitLength != b.BitLength {
			return berValueUnknown
		}
		// X.690 (02/2021) §8.6.2.2: a difference in unused bits
		// is representational, so let the stream comparison decide
		// whether the caller explicitly changed the received form.
		full := a.BitLength / 8
		if !bytes.Equal(a.Bytes[:full], b.Bytes[:full]) {
			return berValueDifferent
		}
		if rem := a.BitLength % 8; rem != 0 {
			mask := ^byte(0) << (8 - rem)
			if a.Bytes[full]&mask != b.Bytes[full]&mask {
				return berValueDifferent
			}
		}
		if bytes.Equal(a.Bytes, b.Bytes) {
			return berValueEqual
		}
		return berValueUnknown
	}
	if left.Type() == rawValueType {
		if !left.CanInterface() || !right.CanInterface() {
			return berValueUnknown
		}
		a, b := left.Interface().(runtime.RawValue), right.Interface().(runtime.RawValue)
		if a.Class == b.Class && a.Tag == b.Tag && a.Constructed == b.Constructed && bytes.Equal(a.Bytes, b.Bytes) {
			return berValueEqual
		}
		// An IMPLICIT site replaces identifier octets but keeps the length
		// and content (X.690 (02/2021) §8.14). A changed identifier alone
		// cannot prove that the encoded value changed; a different suffix
		// or primitive/constructed form can (X.690 (02/2021) §8.1.2).
		aTag, aLength, aErr := DecodeTag(a.Bytes)
		bTag, bLength, bErr := DecodeTag(b.Bytes)
		if aErr == nil && bErr == nil &&
			(aTag.Constructed != bTag.Constructed || !bytes.Equal(a.Bytes[aLength:], b.Bytes[bLength:])) {
			return berValueDifferent
		}
		return berValueUnknown
	}
	if left.Type() == objectIdentifierType {
		if !left.CanInterface() || !right.CanInterface() {
			return berValueUnknown
		}
		return berComparison(left.Interface().(runtime.ObjectIdentifier) == right.Interface().(runtime.ObjectIdentifier))
	}
	if left.Type() == relativeObjectIdentifierType {
		if !left.CanInterface() || !right.CanInterface() {
			return berValueUnknown
		}
		return berComparison(left.Interface().(runtime.RelativeObjectIdentifier) == right.Interface().(runtime.RelativeObjectIdentifier))
	}
	switch left.Kind() {
	case reflect.Bool:
		return berComparison(left.Bool() == right.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return berComparison(left.Int() == right.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return berComparison(left.Uint() == right.Uint())
	case reflect.Float32, reflect.Float64:
		// X.690 (02/2021) §8.5.9 gives NOT-A-NUMBER one abstract
		// value and distinguishes minus zero from plus zero.
		a, b := left.Float(), right.Float()
		if math.IsNaN(a) || math.IsNaN(b) {
			return berComparison(math.IsNaN(a) && math.IsNaN(b))
		}
		if a == 0 && b == 0 {
			return berComparison(math.Signbit(a) == math.Signbit(b))
		}
		return berComparison(a == b)
	case reflect.Complex64, reflect.Complex128:
		return berValueUnknown
	case reflect.String:
		return berComparison(left.String() == right.String())
	case reflect.Pointer:
		if left.IsNil() || right.IsNil() {
			if left.IsNil() == right.IsNil() {
				return berValueEqual
			}
			return berValueUnknown
		}
		if left.Type() == replayNodeType || left.Type() == replayStateType {
			if left.Pointer() == right.Pointer() {
				return berValueEqual
			}
			return berValueUnknown
		}
		if left.Type().Elem().Size() == 0 {
			// Go spec, Size and alignment guarantees: distinct zero-size
			// variables may share an address. The pointee has no value bits.
			return berValueEqual
		}
		if left.Pointer() == right.Pointer() {
			return berValueUnknown
		}
		return compareBERValueNodesReference(left.Elem(), right.Elem(), depth+1, nodeValues)
	case reflect.Interface:
		if left.IsNil() || right.IsNil() {
			if left.IsNil() == right.IsNil() {
				return berValueEqual
			}
			return berValueUnknown
		}
		return compareBERValueNodesReference(left.Elem(), right.Elem(), depth+1, nodeValues)
	case reflect.Slice, reflect.Array:
		if left.Len() != right.Len() {
			return berValueDifferent
		}
		if left.Kind() == reflect.Slice && left.Type().Elem().Kind() == reflect.Uint8 {
			return berComparison(bytes.Equal(left.Bytes(), right.Bytes()))
		}
		result := berValueEqual
		for index := 0; index < left.Len(); index++ {
			switch compareBERValueNodesReference(left.Index(index), right.Index(index), depth+1, nodeValues) {
			case berValueDifferent:
				return berValueDifferent
			case berValueUnknown:
				result = berValueUnknown
			}
		}
		return result
	case reflect.Struct:
		// Generated CHOICEs have an untagged Choice discriminator and a
		// replay-node field. Only the selected alternative is a value:
		// X.680 (02/2021) §29. An ordinary SEQUENCE component named Choice
		// has an asn1 tag and therefore does not meet this layout.
		selected := -1
		if left.NumField() > 1 && left.Type().Field(0).Name == "Choice" && left.Type().Field(0).Type.Kind() == reflect.Int {
			if _, tagged := left.Type().Field(0).Tag.Lookup("asn1"); !tagged {
				hasReplayNode := false
				choiceExtension := -1
				alternatives := make([]int, 0, left.NumField()-1)
				for index := 1; index < left.NumField(); index++ {
					field := left.Type().Field(index)
					if field.Type == replayNodeType {
						hasReplayNode = true
					} else if field.Type == reflect.TypeFor[*runtime.BERChoiceExtension]() {
						// X.680 (02/2021) §§29.1, 52.1: this holder
						// is outside the numbered known alternatives.
						choiceExtension = index
					} else if field.PkgPath == "" {
						// X.680 (02/2021) §29: a known alternative may
						// have the ASN.1 identifier unknownExtension.
						alternatives = append(alternatives, index)
					}
				}
				if hasReplayNode {
					leftChoice, rightChoice := int(left.Field(0).Int()), int(right.Field(0).Int())
					if choiceExtension >= 0 && (leftChoice >= 1 || rightChoice >= 1) &&
						(!left.Field(choiceExtension).IsNil() || !right.Field(choiceExtension).IsNil()) {
						return berValueUnknown
					}
					if leftChoice < 1 || rightChoice < 1 || leftChoice > len(alternatives) || rightChoice > len(alternatives) {
						return berValueUnknown
					}
					if left.Field(0).Int() != right.Field(0).Int() {
						return berValueDifferent
					}
					selected = alternatives[leftChoice-1]
				}
			}
		}
		result := berValueEqual
		for index := 0; index < left.NumField(); index++ {
			if selected >= 0 && index != selected && left.Type().Field(index).Type != replayNodeType {
				continue
			}
			field := left.Type().Field(index)
			var comparison berValueComparison
			if field.PkgPath == "" && field.Tag.Get("asn1") == "-" && field.Name == "ExtData_" && field.Type == reflect.TypeFor[[][]byte]() {
				// The generated SEQUENCE and SET encoders append each complete
				// unknown TLV verbatim (X.690 (02/2021) §§8.9.2, 8.11.2).
				comparison = compareBERValueNodesReference(left.Field(index), right.Field(index), depth+1, nodeValues)
			} else if field.PkgPath == "" && strings.Contains(","+field.Tag.Get("asn1")+",", ",optional,") &&
				berOptionalPresenceDiffers(left.Field(index), right.Field(index)) {
				// Generated BER emits OPTIONAL and DEFAULT components exactly
				// when their fields are non-nil. X.690 (02/2021) §§8.9.3,
				// 8.11.3 permit either form for DEFAULT; §11.5 restricts CER/DER.
				comparison = berValueDifferent
			} else {
				comparison = compareBERValueNodesReference(left.Field(index), right.Field(index), depth+1, nodeValues)
			}
			switch comparison {
			case berValueDifferent:
				if field.PkgPath == "" && (field.Tag.Get("asn1") != "-" || field.Name == "ExtData_" && field.Type == reflect.TypeFor[[][]byte]()) {
					result = berValueDifferent
					break
				}
				if result != berValueDifferent {
					result = berValueUnknown
				}
			case berValueUnknown:
				if result != berValueDifferent {
					result = berValueUnknown
				}
			}
		}
		if nodeValues != nil {
			for index := 0; index < left.NumField(); index++ {
				field := left.Field(index)
				baselineField := right.Field(index)
				if field.Type() == replayNodeType && !field.IsNil() && !baselineField.IsNil() && field.Pointer() == baselineField.Pointer() {
					nodeValues.put(field.Pointer(), result)
				}
			}
		}
		return result
	case reflect.Map:
		if left.Len() != right.Len() {
			return berValueDifferent
		}
		result := berValueEqual
		for iterator := left.MapRange(); iterator.Next(); {
			other := right.MapIndex(iterator.Key())
			if !other.IsValid() {
				return berValueDifferent
			}
			switch compareBERValueNodesReference(iterator.Value(), other, depth+1, nodeValues) {
			case berValueDifferent:
				return berValueDifferent
			case berValueUnknown:
				result = berValueUnknown
			}
		}
		return result
	case reflect.Func:
		if left.IsNil() && right.IsNil() {
			return berValueEqual
		}
		return berValueUnknown
	default:
		return berValueUnknown
	}
}
