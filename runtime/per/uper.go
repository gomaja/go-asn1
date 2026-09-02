package per

import (
	"fmt"
	"math"
	"math/bits"
	"strings"
	"unicode/utf8"
)

// BitWidth returns the number of bits needed to represent values 0..rangeVal.
func BitWidth(rangeVal int64) int {
	if rangeVal <= 0 {
		return 0
	}
	return bits.Len64(uint64(rangeVal))
}

// EncodeBoolean encodes a boolean as 1 bit.
func EncodeBoolean(bb *BitBuffer, v bool) error {
	if v {
		return bb.WriteBit(1)
	}
	return bb.WriteBit(0)
}

// DecodeBoolean decodes a boolean from 1 bit.
func DecodeBoolean(bb *BitBuffer) (bool, error) {
	bit, err := bb.ReadBit()
	if err != nil {
		return false, err
	}
	return bit != 0, nil
}

// EncodeConstrainedWholeNumber encodes v in [lb..ub] using minimal bits.
// ITU-T X.691 (02/2021), clause 11.5.
func EncodeConstrainedWholeNumber(bb *BitBuffer, v, lb, ub int64) error {
	if lb > ub {
		return fmt.Errorf("%w: invalid range [%d..%d]", ErrInvalidValue, lb, ub)
	}
	if v < lb || v > ub {
		return fmt.Errorf("%w: %d not in [%d..%d]", ErrConstraintViolation, v, lb, ub)
	}
	rangeValue := uint64(ub) - uint64(lb)
	if rangeValue == 0 {
		return nil // no bits needed
	}
	offset := uint64(v) - uint64(lb)
	return bb.WriteBits(offset, bits.Len64(rangeValue))
}

// DecodeConstrainedWholeNumber decodes a value from [lb..ub].
func DecodeConstrainedWholeNumber(bb *BitBuffer, lb, ub int64) (int64, error) {
	if lb > ub {
		return 0, fmt.Errorf("%w: invalid range [%d..%d]", ErrInvalidValue, lb, ub)
	}
	rangeValue := uint64(ub) - uint64(lb)
	if rangeValue == 0 {
		return lb, nil
	}
	offset, err := bb.ReadBits(bits.Len64(rangeValue))
	if err != nil {
		return 0, err
	}
	if offset > rangeValue {
		return 0, fmt.Errorf("%w: constrained offset %d exceeds range [%d..%d]", ErrInvalidValue, offset, lb, ub)
	}
	return addNonNegativeOffset(lb, offset)
}

// EncodeNormallySmallNonNegative encodes a normally small non-negative whole number.
// X.691 Section 11.6. Used for CHOICE extension index, bitmap lengths.
func EncodeNormallySmallNonNegative(bb *BitBuffer, v int64) error {
	if v < 0 {
		return fmt.Errorf("%w: negative value %d", ErrInvalidValue, v)
	}
	if v < 64 {
		if err := bb.WriteBit(0); err != nil {
			return err
		}
		return bb.WriteBits(uint64(v), 6)
	}
	if err := bb.WriteBit(1); err != nil {
		return err
	}
	return EncodeSemiConstrainedWholeNumber(bb, v, 0)
}

// DecodeNormallySmallNonNegative decodes a normally small non-negative whole number.
func DecodeNormallySmallNonNegative(bb *BitBuffer) (int64, error) {
	bit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		val, err := bb.ReadBits(6)
		if err != nil {
			return 0, err
		}
		return int64(val), nil
	}
	return DecodeSemiConstrainedWholeNumber(bb, 0)
}

// DecodeExtensionBitmap decodes the highest extension index and presence bits.
func DecodeExtensionBitmap(bb *BitBuffer) (int64, []bool, error) {
	count, err := DecodeNormallySmallNonNegative(bb)
	if err != nil {
		return 0, nil, err
	}
	return decodeExtensionBitmapBits(bb, count)
}

func decodeExtensionBitmapBits(bb *BitBuffer, count int64) (int64, []bool, error) {
	remaining := bb.BitsRemaining()
	if count < 0 {
		return 0, nil, fmt.Errorf("%w: negative extension bitmap index %d", ErrInvalidValue, count)
	}
	// count is the highest index, so the bitmap contains count+1 bits.
	if count >= int64(remaining) {
		return 0, nil, fmt.Errorf("%w: extension bitmap index %d exceeds %d remaining bits", ErrTruncated, count, remaining)
	}
	present := make([]bool, int(count)+1)
	for i := range present {
		value, err := DecodeBoolean(bb)
		if err != nil {
			return 0, nil, err
		}
		present[i] = value
	}
	return count, present, nil
}

// EncodeSemiConstrainedWholeNumber encodes v with known lower bound but no upper bound.
// ITU-T X.691 (02/2021), clause 11.7.
func EncodeSemiConstrainedWholeNumber(bb *BitBuffer, v, lb int64) error {
	if v < lb {
		return fmt.Errorf("%w: %d below lower bound %d", ErrConstraintViolation, v, lb)
	}
	return encodeNonNegativeBinaryIntegerWithLength(bb, uint64(v)-uint64(lb))
}

// DecodeSemiConstrainedWholeNumber decodes a semi-constrained whole number.
func DecodeSemiConstrainedWholeNumber(bb *BitBuffer, lb int64) (int64, error) {
	offset, err := decodeNonNegativeBinaryIntegerWithLength(bb)
	if err != nil {
		return 0, err
	}
	return addNonNegativeOffset(lb, offset)
}

// EncodeUnconstrainedWholeNumber encodes a signed integer with no bounds.
// ITU-T X.691 (02/2021), clause 11.8.
func EncodeUnconstrainedWholeNumber(bb *BitBuffer, v int64) error {
	// Encode as 2's complement with length determinant.
	var buf []byte
	if v >= 0 {
		if v == 0 {
			buf = []byte{0}
		} else {
			buf = minimalUnsignedBytes(uint64(v))
			// If high bit set, prepend a 0x00 byte for sign.
			if buf[0]&0x80 != 0 {
				buf = append([]byte{0}, buf...)
			}
		}
	} else {
		buf = minimalSignedNegBytes(v)
	}
	if err := EncodeUnconstrainedLength(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

// DecodeUnconstrainedWholeNumber decodes an unconstrained signed integer.
func DecodeUnconstrainedWholeNumber(bb *BitBuffer) (int64, error) {
	length, err := DecodeUnconstrainedLength(bb)
	if err != nil {
		return 0, err
	}
	if length == 0 {
		return 0, nil
	}
	data, err := bb.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}
	return twosComplementToInt64(data), nil
}

// EncodeUnconstrainedLength encodes a length determinant with no constraints.
// X.691 Section 11.9.
func EncodeUnconstrainedLength(bb *BitBuffer, n int64) error {
	if n < 0 {
		return fmt.Errorf("%w: negative length %d", ErrInvalidValue, n)
	}
	if n < 128 {
		// Short form: 0xxxxxxx
		return bb.WriteBits(uint64(n), 8)
	}
	if n < 16384 {
		// Long form: 10xxxxxx xxxxxxxx
		return bb.WriteBits(0x8000|uint64(n), 16)
	}
	// Fragmentation: not commonly needed, return error for now.
	return fmt.Errorf("per: length %d requires fragmentation (not yet supported)", n)
}

// DecodeUnconstrainedLength decodes an unconstrained length determinant.
func DecodeUnconstrainedLength(bb *BitBuffer) (int64, error) {
	length, more, _, err := decodeLengthFragmentDeterminant(bb, false)
	if err != nil {
		return 0, err
	}
	if more {
		return 0, fmt.Errorf("%w: fragmented determinant requires interleaved value decoding", ErrInvalidValue)
	}
	return length, nil
}

// EncodeInteger encodes an integer using the appropriate method based on constraints.
func EncodeInteger(bb *BitBuffer, v int64, lb, ub *int64, extensible bool) error {
	if extensible {
		inRoot := true
		if lb != nil && v < *lb {
			inRoot = false
		}
		if ub != nil && v > *ub {
			inRoot = false
		}
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return EncodeUnconstrainedWholeNumber(bb, v)
		}
	}
	if lb != nil && ub != nil {
		return EncodeConstrainedWholeNumber(bb, v, *lb, *ub)
	}
	if lb != nil {
		return EncodeSemiConstrainedWholeNumber(bb, v, *lb)
	}
	return EncodeUnconstrainedWholeNumber(bb, v)
}

// DecodeInteger decodes an integer using the appropriate method based on constraints.
func DecodeInteger(bb *BitBuffer, lb, ub *int64, extensible bool) (int64, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			return DecodeUnconstrainedWholeNumber(bb)
		}
	}
	if lb != nil && ub != nil {
		return DecodeConstrainedWholeNumber(bb, *lb, *ub)
	}
	if lb != nil {
		return DecodeSemiConstrainedWholeNumber(bb, *lb)
	}
	return DecodeUnconstrainedWholeNumber(bb)
}

// EncodeEnumerated encodes an enumerated value.
// rootCount = number of root enumeration values, extensible = has "..." marker.
func EncodeEnumerated(bb *BitBuffer, v int64, rootCount int, extensible bool) error {
	if extensible {
		isExtension := v >= int64(rootCount)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			return EncodeNormallySmallNonNegative(bb, v-int64(rootCount))
		}
	}
	if rootCount <= 1 {
		return nil // single value, no bits needed
	}
	return EncodeConstrainedWholeNumber(bb, v, 0, int64(rootCount-1))
}

// DecodeEnumerated decodes an enumerated value.
func DecodeEnumerated(bb *BitBuffer, rootCount int, extensible bool) (int64, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			extIdx, err := DecodeNormallySmallNonNegative(bb)
			if err != nil {
				return 0, err
			}
			return int64(rootCount) + extIdx, nil
		}
	}
	if rootCount <= 1 {
		return 0, nil
	}
	return DecodeConstrainedWholeNumber(bb, 0, int64(rootCount-1))
}

// EncodeBitString encodes a bit string.
// If constrained and lb == ub: fixed size, no length.
// If constrained and ub <= 65536: constrained length + bits.
// Otherwise: unconstrained length + bits.
func EncodeBitString(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained bool) error {
	return EncodeBitStringExt(bb, data, bitLen, lb, ub, constrained, false)
}

// EncodeBitStringExt encodes a BIT STRING with optional SIZE extensibility.
func EncodeBitStringExt(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained, extensible bool) error {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return err
	}
	if extensible && constrained {
		inRoot := int64(bitLen) >= lb && int64(bitLen) <= ub
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeLengthDelimitedBits(bb, data, bitLen, false)
		}
	}
	if err := validateRootSize(int64(bitLen), lb, ub, constrained); err != nil {
		return err
	}
	if constrained && lb == ub && ub < 64*1024 {
		// Fixed size — write exactly lb bits.
		if int64(bitLen) != lb {
			return fmt.Errorf("%w: BIT STRING length %d does not match fixed SIZE(%d)", ErrConstraintViolation, bitLen, lb)
		}
		return bb.WriteBitsFromBytes(data, int(lb))
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumber(bb, int64(bitLen), lb, ub); err != nil {
			return err
		}
		return bb.WriteBitsFromBytes(data, bitLen)
	}
	return encodeLengthDelimitedBits(bb, data, bitLen, false)
}

// DecodeBitString decodes a bit string. Returns (bytes, bitLength, error).
func DecodeBitString(bb *BitBuffer, lb, ub int64, constrained bool) ([]byte, int, error) {
	return DecodeBitStringExt(bb, lb, ub, constrained, false)
}

// DecodeBitStringExt decodes a BIT STRING with optional SIZE extensibility.
func DecodeBitStringExt(bb *BitBuffer, lb, ub int64, constrained, extensible bool) ([]byte, int, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return nil, 0, err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return nil, 0, err
		}
		if isExtension {
			return decodeLengthDelimitedBits(bb, false)
		}
	}
	if constrained && lb == ub && ub < 64*1024 {
		data, err := bb.ReadBitsToBytes(int(lb))
		return data, int(lb), err
	}
	var bitLen int64
	var err error
	if constrained && ub < 65536 {
		bitLen, err = DecodeConstrainedWholeNumber(bb, lb, ub)
	} else {
		var data []byte
		var decodedLength int
		data, decodedLength, err = decodeLengthDelimitedBitsBounded(bb, false, rootSizeMaximum(ub, constrained))
		bitLen = int64(decodedLength)
		if err == nil {
			err = validateRootSize(bitLen, lb, ub, constrained)
		}
		return data, decodedLength, err
	}
	if err != nil {
		return nil, 0, err
	}
	if err := validateRootSize(bitLen, lb, ub, constrained); err != nil {
		return nil, 0, err
	}
	data, err := bb.ReadBitsToBytes(int(bitLen))
	return data, int(bitLen), err
}

// EncodeOctetString encodes an octet string.
// If constrained and lb == ub: fixed size, no length.
// If constrained and ub <= 65536: constrained length + octets.
// Otherwise: unconstrained length + octets.
func EncodeOctetString(bb *BitBuffer, data []byte, lb, ub int64, constrained bool) error {
	return EncodeOctetStringExt(bb, data, lb, ub, constrained, false)
}

// EncodeOctetStringExt implements the SIZE extension bit required by
// ITU-T X.691 (02/2021) Section 17.3.
func EncodeOctetStringExt(bb *BitBuffer, data []byte, lb, ub int64, constrained, extensible bool) error {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return err
	}
	length := int64(len(data))
	if extensible && constrained {
		inRoot := length >= lb && length <= ub
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeLengthDelimitedOctets(bb, data, false)
		}
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return err
	}
	if constrained && lb == ub && ub < 64*1024 {
		// Fixed size — write exactly lb octets.
		if int64(len(data)) != lb {
			return fmt.Errorf("%w: OCTET STRING length %d does not match fixed SIZE(%d)", ErrConstraintViolation, len(data), lb)
		}
		return bb.WriteBytes(data)
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumber(bb, length, lb, ub); err != nil {
			return err
		}
		return bb.WriteBytes(data)
	}
	return encodeLengthDelimitedOctets(bb, data, false)
}

// DecodeOctetString decodes an octet string.
func DecodeOctetString(bb *BitBuffer, lb, ub int64, constrained bool) ([]byte, error) {
	return DecodeOctetStringExt(bb, lb, ub, constrained, false)
}

// DecodeOctetStringExt implements the SIZE extension bit required by
// ITU-T X.691 (02/2021) Section 17.3.
func DecodeOctetStringExt(bb *BitBuffer, lb, ub int64, constrained, extensible bool) ([]byte, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return nil, err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return nil, err
		}
		if isExtension {
			return decodeLengthDelimitedOctets(bb, false)
		}
	}
	if constrained && lb == ub && ub < 64*1024 {
		return bb.ReadBytes(int(lb))
	}
	var length int64
	var err error
	if constrained && ub < 65536 {
		length, err = DecodeConstrainedWholeNumber(bb, lb, ub)
	} else {
		var data []byte
		data, err = decodeLengthDelimitedOctetsBounded(bb, false, rootSizeMaximum(ub, constrained))
		length = int64(len(data))
		if err == nil {
			err = validateRootSize(length, lb, ub, constrained)
		}
		return data, err
	}
	if err != nil {
		return nil, err
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return nil, err
	}
	return bb.ReadBytes(int(length))
}

// EncodeNull is a no-op (NULL = 0 bits in UPER).
func EncodeNull(_ *BitBuffer) error {
	return nil
}

// DecodeNull is a no-op.
func DecodeNull(_ *BitBuffer) error {
	return nil
}

// EncodeKnownMultiplierString encodes a string with known character set.
// bitsPerChar is the bits per character (e.g., 7 for IA5String/VisibleString, 4 for NumericString).
func EncodeKnownMultiplierString(bb *BitBuffer, s string, bitsPerChar int, lb, ub int64, constrained bool) error {
	return EncodeKnownMultiplierStringExt(bb, s, bitsPerChar, lb, ub, constrained, false)
}

// EncodeKnownMultiplierStringExt implements the size extension bit required
// by ITU-T X.691 (02/2021) Section 30.4.
func EncodeKnownMultiplierStringExt(bb *BitBuffer, s string, bitsPerChar int, lb, ub int64, constrained, extensible bool) error {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return err
	}
	if err := validateKnownMultiplierWidth(bitsPerChar); err != nil {
		return err
	}
	if err := validateKnownMultiplierStringValue(s, bitsPerChar); err != nil {
		return err
	}
	length := knownMultiplierStringLength(s, bitsPerChar)
	if extensible && constrained {
		inRoot := length >= lb && length <= ub
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeLengthDelimitedKnownMultiplierString(bb, s, bitsPerChar, false)
		}
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return err
	}
	if constrained && lb == ub && ub < 64*1024 {
		// Fixed size — write exactly lb characters.
		if length != lb {
			return fmt.Errorf("%w: string length %d does not match fixed SIZE(%d)", ErrConstraintViolation, length, lb)
		}
		return writeKnownMultiplierString(bb, s, bitsPerChar)
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumber(bb, length, lb, ub); err != nil {
			return err
		}
	} else {
		return encodeLengthDelimitedKnownMultiplierString(bb, s, bitsPerChar, false)
	}
	return writeKnownMultiplierString(bb, s, bitsPerChar)
}

// DecodeKnownMultiplierString decodes a string with known character set.
func DecodeKnownMultiplierString(bb *BitBuffer, bitsPerChar int, lb, ub int64, constrained bool) (string, error) {
	return DecodeKnownMultiplierStringExt(bb, bitsPerChar, lb, ub, constrained, false)
}

// DecodeKnownMultiplierStringExt implements the size extension bit required
// by ITU-T X.691 (02/2021) Section 30.4.
func DecodeKnownMultiplierStringExt(bb *BitBuffer, bitsPerChar int, lb, ub int64, constrained, extensible bool) (string, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return "", err
	}
	if err := validateKnownMultiplierWidth(bitsPerChar); err != nil {
		return "", err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return "", err
		}
		if isExtension {
			value, _, err := decodeLengthDelimitedKnownMultiplierString(bb, bitsPerChar, false)
			return value, err
		}
	}
	var length int64
	var err error
	if constrained && lb == ub && ub < 64*1024 {
		length = lb
	} else if constrained && ub < 65536 {
		length, err = DecodeConstrainedWholeNumber(bb, lb, ub)
		if err != nil {
			return "", err
		}
	} else {
		value, decodedLength, err := decodeLengthDelimitedKnownMultiplierStringBounded(bb, bitsPerChar, false, rootSizeMaximum(ub, constrained))
		if err != nil {
			return "", err
		}
		if err := validateRootSize(decodedLength, lb, ub, constrained); err != nil {
			return "", err
		}
		return value, nil
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return "", err
	}
	return readKnownMultiplierString(bb, length, bitsPerChar)
}

// EncodeOpenType wraps already-encoded bytes with an unconstrained length determinant.
// Used for extension additions and open type fields.
func EncodeOpenType(bb *BitBuffer, data []byte) error {
	return encodeLengthDelimitedOctets(bb, data, false)
}

// DecodeOpenType decodes an open type value.
func DecodeOpenType(bb *BitBuffer) ([]byte, error) {
	return decodeLengthDelimitedOctets(bb, false)
}

// EncodeChoiceIndex encodes a CHOICE index for root alternatives.
func EncodeChoiceIndex(bb *BitBuffer, index int64, numAlternatives int, extensible bool) error {
	if extensible {
		isExtension := index >= int64(numAlternatives)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			return EncodeNormallySmallNonNegative(bb, index-int64(numAlternatives))
		}
	}
	if numAlternatives <= 1 {
		return nil
	}
	return EncodeConstrainedWholeNumber(bb, index, 0, int64(numAlternatives-1))
}

// DecodeChoiceIndex decodes a CHOICE index.
func DecodeChoiceIndex(bb *BitBuffer, numAlternatives int, extensible bool) (int64, bool, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, false, err
		}
		if isExtension {
			idx, err := DecodeNormallySmallNonNegative(bb)
			if err != nil {
				return 0, true, err
			}
			return int64(numAlternatives) + idx, true, nil
		}
	}
	if numAlternatives <= 1 {
		return 0, false, nil
	}
	idx, err := DecodeConstrainedWholeNumber(bb, 0, int64(numAlternatives-1))
	return idx, false, err
}

// --- internal helpers ---

func encodeLengthDelimitedBits(bb *BitBuffer, data []byte, bitLength int, aligned bool) error {
	if bitLength < 0 || (bitLength+7)/8 > len(data) {
		return fmt.Errorf("%w: BIT STRING length %d exceeds %d source octets", ErrInvalidValue, bitLength, len(data))
	}
	return EncodeLengthFragments(bb, int64(bitLength), aligned, func(offset, length int64) error {
		if aligned {
			bb.AlignToOctetWrite()
		}
		if offset%8 != 0 {
			return fmt.Errorf("%w: BIT STRING fragment offset %d is not octet-aligned", ErrInvalidValue, offset)
		}
		return bb.WriteBitsFromBytes(data[int(offset/8):], int(length))
	})
}

func decodeLengthDelimitedBits(bb *BitBuffer, aligned bool) ([]byte, int, error) {
	return decodeLengthDelimitedBitsBounded(bb, aligned, math.MaxInt64)
}

func decodeLengthDelimitedBitsBounded(bb *BitBuffer, aligned bool, maximum int64) ([]byte, int, error) {
	var result []byte
	total, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(_ int64, length int64) error {
		if aligned {
			bb.AlignToOctetRead()
		}
		if length > int64(bb.BitsRemaining()) {
			return fmt.Errorf("%w: BIT STRING fragment requires %d bits with %d remaining", ErrTruncated, length, bb.BitsRemaining())
		}
		fragment, err := bb.ReadBitsToBytes(int(length))
		if err != nil {
			return err
		}
		result = append(result, fragment...)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	maximumInt := int64(^uint(0) >> 1)
	if total > maximumInt {
		return nil, 0, fmt.Errorf("%w: BIT STRING length %d overflows int", ErrInvalidValue, total)
	}
	return result, int(total), nil
}

func encodeLengthDelimitedKnownMultiplierString(bb *BitBuffer, value string, bitsPerChar int, aligned bool) error {
	if err := validateKnownMultiplierStringValue(value, bitsPerChar); err != nil {
		return err
	}
	length := knownMultiplierStringLength(value, bitsPerChar)
	var runes []rune
	if bitsPerChar > 8 {
		runes = []rune(value)
	}
	return EncodeLengthFragments(bb, length, aligned, func(offset, fragmentLength int64) error {
		if aligned {
			bb.AlignToOctetWrite()
		}
		if bitsPerChar <= 8 {
			return writeKnownMultiplierString(bb, value[int(offset):int(offset+fragmentLength)], bitsPerChar)
		}
		for _, character := range runes[int(offset):int(offset+fragmentLength)] {
			if err := bb.WriteBits(uint64(character), bitsPerChar); err != nil {
				return err
			}
		}
		return nil
	})
}

func decodeLengthDelimitedKnownMultiplierString(bb *BitBuffer, bitsPerChar int, aligned bool) (string, int64, error) {
	return decodeLengthDelimitedKnownMultiplierStringBounded(bb, bitsPerChar, aligned, math.MaxInt64)
}

func decodeLengthDelimitedKnownMultiplierStringBounded(bb *BitBuffer, bitsPerChar int, aligned bool, maximum int64) (string, int64, error) {
	var result strings.Builder
	total, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(_ int64, length int64) error {
		if aligned {
			bb.AlignToOctetRead()
		}
		fragment, err := readKnownMultiplierString(bb, length, bitsPerChar)
		if err != nil {
			return err
		}
		_, err = result.WriteString(fragment)
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return result.String(), total, nil
}

func encodeNonNegativeBinaryIntegerWithLength(bb *BitBuffer, v uint64) error {
	buf := minimalUnsignedBytes(v)
	if err := EncodeUnconstrainedLength(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

func decodeNonNegativeBinaryIntegerWithLength(bb *BitBuffer) (uint64, error) {
	length, err := DecodeUnconstrainedLength(bb)
	if err != nil {
		return 0, err
	}
	if length == 0 {
		return 0, nil
	}
	if length > 8 {
		return 0, fmt.Errorf("%w: non-negative integer uses %d octets, maximum is 8", ErrInvalidValue, length)
	}
	data, err := bb.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}
	var val uint64
	for _, b := range data {
		val = (val << 8) | uint64(b)
	}
	return val, nil
}

func addNonNegativeOffset(lb int64, offset uint64) (int64, error) {
	maxOffset := uint64(math.MaxInt64)
	if lb < 0 {
		maxOffset += uint64(-(lb + 1)) + 1
	} else {
		maxOffset -= uint64(lb)
	}
	if offset > maxOffset {
		return 0, fmt.Errorf("%w: non-negative offset %d overflows int64 lower bound %d", ErrInvalidValue, offset, lb)
	}
	if offset <= math.MaxInt64 {
		return lb + int64(offset), nil
	}
	absLowerBound := uint64(-(lb + 1)) + 1
	return int64(offset - absLowerBound), nil
}

func validateSizeBounds(lb, ub int64, constrained bool) error {
	if constrained && (lb < 0 || ub < 0 || lb > ub) {
		return fmt.Errorf("%w: invalid SIZE range [%d..%d]", ErrInvalidValue, lb, ub)
	}
	return nil
}

func validateRootSize(length, lb, ub int64, constrained bool) error {
	if constrained && (length < lb || length > ub) {
		return fmt.Errorf("%w: length %d not in SIZE(%d..%d)", ErrConstraintViolation, length, lb, ub)
	}
	return nil
}

func rootSizeMaximum(ub int64, constrained bool) int64 {
	if constrained {
		return ub
	}
	return math.MaxInt64
}

func validateKnownMultiplierWidth(bitsPerChar int) error {
	if bitsPerChar < 1 || bitsPerChar > 32 {
		return fmt.Errorf("%w: character width %d bits is outside [1..32]", ErrInvalidValue, bitsPerChar)
	}
	return nil
}

func knownMultiplierStringLength(value string, bitsPerChar int) int64 {
	if bitsPerChar <= 8 {
		return int64(len(value))
	}
	return int64(utf8.RuneCountInString(value))
}

func knownMultiplierPayloadBits(length int64, bitsPerChar int) (int, error) {
	if length < 0 {
		return 0, fmt.Errorf("%w: negative character-string length %d", ErrInvalidValue, length)
	}
	if err := validateKnownMultiplierWidth(bitsPerChar); err != nil {
		return 0, err
	}
	maximumInt := int64(^uint(0) >> 1)
	if length > maximumInt/int64(bitsPerChar) {
		return 0, fmt.Errorf("%w: character-string payload length overflows int", ErrInvalidValue)
	}
	return int(length) * bitsPerChar, nil
}

func writeKnownMultiplierString(bb *BitBuffer, value string, bitsPerChar int) error {
	if err := validateKnownMultiplierStringValue(value, bitsPerChar); err != nil {
		return err
	}

	if bitsPerChar <= 8 {
		for _, character := range []byte(value) {
			if err := bb.WriteBits(uint64(character), bitsPerChar); err != nil {
				return err
			}
		}
		return nil
	}
	for _, character := range value {
		if err := bb.WriteBits(uint64(character), bitsPerChar); err != nil {
			return err
		}
	}
	return nil
}

func validateKnownMultiplierStringValue(value string, bitsPerChar int) error {
	if err := validateKnownMultiplierWidth(bitsPerChar); err != nil {
		return err
	}
	if bitsPerChar > 8 && !utf8.ValidString(value) {
		return fmt.Errorf("%w: wide character string is not valid UTF-8", ErrInvalidValue)
	}
	maximum := uint64(1) << bitsPerChar
	if bitsPerChar <= 8 {
		for _, character := range []byte(value) {
			if uint64(character) >= maximum {
				return fmt.Errorf("%w: character %#x does not fit in %d bits", ErrConstraintViolation, character, bitsPerChar)
			}
		}
		return nil
	}
	for _, character := range value {
		if uint64(character) >= maximum {
			return fmt.Errorf("%w: character %U does not fit in %d bits", ErrConstraintViolation, character, bitsPerChar)
		}
	}
	return nil
}

func readKnownMultiplierString(bb *BitBuffer, length int64, bitsPerChar int) (string, error) {
	payloadBits, err := knownMultiplierPayloadBits(length, bitsPerChar)
	if err != nil {
		return "", err
	}
	if payloadBits > bb.BitsRemaining() {
		return "", fmt.Errorf("%w: character string requires %d bits with %d remaining", ErrTruncated, payloadBits, bb.BitsRemaining())
	}
	if bitsPerChar <= 8 {
		result := make([]byte, int(length))
		for index := range result {
			value, err := bb.ReadBits(bitsPerChar)
			if err != nil {
				return "", err
			}
			result[index] = byte(value)
		}
		return string(result), nil
	}
	result := make([]rune, int(length))
	for index := range result {
		value, err := bb.ReadBits(bitsPerChar)
		if err != nil {
			return "", err
		}
		character := rune(value)
		if !utf8.ValidRune(character) {
			return "", fmt.Errorf("%w: invalid Unicode scalar value U+%X", ErrInvalidValue, value)
		}
		result[index] = character
	}
	return string(result), nil
}

func minimalUnsignedBytes(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	n := (bits.Len64(v) + 7) / 8
	buf := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte(v)
		v >>= 8
	}
	return buf
}

func minimalSignedNegBytes(v int64) []byte {
	// Encode negative v as minimal 2's complement.
	uv := uint64(v)
	// Find minimal byte count: start from 1 and check sign extension.
	for n := 1; n <= 8; n++ {
		// Check if n bytes can represent v.
		shift := uint(n * 8)
		if n == 8 || (int64(uv<<(64-shift))>>(64-shift)) == v {
			buf := make([]byte, n)
			for i := n - 1; i >= 0; i-- {
				buf[i] = byte(uv)
				uv >>= 8
			}
			return buf
		}
	}
	return nil
}

func twosComplementToInt64(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	// Sign extend.
	var val int64
	if data[0]&0x80 != 0 {
		val = -1
	}
	for _, b := range data {
		val = (val << 8) | int64(b)
	}
	return val
}
