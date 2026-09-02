package per

import (
	"fmt"
	"math/bits"
)

// APER (Aligned PER) encoding primitives.
// Per ITU-T X.691, APER differs from UPER in octet-alignment of certain fields.

// EncodeConstrainedWholeNumberAligned encodes v in [lb..ub] using APER rules.
// ITU-T X.691 (02/2021), clauses 11.5.6-11.5.7.
func EncodeConstrainedWholeNumberAligned(bb *BitBuffer, v, lb, ub int64) error {
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
	// rangeVal = ub - lb; number of values = rangeVal + 1.
	// Per ITU-T X.691 (02/2021), clauses 11.5.6-11.5.7:
	//   numValues ≤ 255 (rangeVal ≤ 254): bit-field of minimum width, NOT aligned
	//   numValues = 256 (rangeVal = 255):  8-bit field, octet-aligned
	//   numValues 257..65536 (rangeVal 256..65535): 16-bit field, octet-aligned
	//   numValues > 65536: length-determinant + value, octet-aligned
	switch {
	case rangeValue < 255:
		// Up to 255 values: minimum bit-field, NOT octet-aligned.
		return bb.WriteBits(offset, bits.Len64(rangeValue))
	case rangeValue == 255:
		// Exactly 256 values: 8-bit field, octet-aligned.
		bb.AlignToOctetWrite()
		return bb.WriteBits(offset, 8)
	case rangeValue < 65536:
		// 257..65536 values: 16-bit field, octet-aligned.
		bb.AlignToOctetWrite()
		return bb.WriteBits(offset, 16)
	default:
		// Range > 65535: length-determinant (NOT aligned) + value bytes (octet-aligned).
		// The length determinant precedes octet alignment of the value.
		n := (bits.Len64(offset) + 7) / 8
		if n == 0 {
			n = 1
		}
		// Length determinant: number of bytes needed, encoded as constrained [1..maxBytes].
		maxBytes := (bits.Len64(rangeValue) + 7) / 8
		if err := EncodeConstrainedWholeNumber(bb, int64(n), 1, int64(maxBytes)); err != nil {
			return err
		}
		bb.AlignToOctetWrite()
		for i := n - 1; i >= 0; i-- {
			if err := bb.WriteBits((offset>>(uint(i)*8))&0xFF, 8); err != nil {
				return err
			}
		}
		return nil
	}
}

// DecodeConstrainedWholeNumberAligned decodes a value from [lb..ub] using APER rules.
func DecodeConstrainedWholeNumberAligned(bb *BitBuffer, lb, ub int64) (int64, error) {
	if lb > ub {
		return 0, fmt.Errorf("%w: invalid range [%d..%d]", ErrInvalidValue, lb, ub)
	}
	rangeValue := uint64(ub) - uint64(lb)
	if rangeValue == 0 {
		return lb, nil
	}
	switch {
	case rangeValue < 255:
		// Up to 255 values: minimum bit-field, NOT octet-aligned.
		offset, err := bb.ReadBits(bits.Len64(rangeValue))
		if err != nil {
			return 0, err
		}
		if offset > rangeValue {
			return 0, fmt.Errorf("%w: constrained offset %d exceeds range [%d..%d]", ErrInvalidValue, offset, lb, ub)
		}
		return addNonNegativeOffset(lb, offset)
	case rangeValue == 255:
		// Exactly 256 values: 8-bit field, octet-aligned.
		bb.AlignToOctetRead()
		offset, err := bb.ReadBits(8)
		if err != nil {
			return 0, err
		}
		return addNonNegativeOffset(lb, offset)
	case rangeValue < 65536:
		bb.AlignToOctetRead()
		offset, err := bb.ReadBits(16)
		if err != nil {
			return 0, err
		}
		if offset > rangeValue {
			return 0, fmt.Errorf("%w: constrained offset %d exceeds range [%d..%d]", ErrInvalidValue, offset, lb, ub)
		}
		return addNonNegativeOffset(lb, offset)
	default:
		// Range > 65535: length-determinant (NOT aligned) + value bytes (octet-aligned).
		// The length determinant precedes octet alignment of the value.
		maxBytes := (bits.Len64(rangeValue) + 7) / 8
		n, err := DecodeConstrainedWholeNumber(bb, 1, int64(maxBytes))
		if err != nil {
			return 0, err
		}
		bb.AlignToOctetRead()
		data, err := bb.ReadBytes(int(n))
		if err != nil {
			return 0, err
		}
		var val uint64
		for _, b := range data {
			val = (val << 8) | uint64(b)
		}
		if val > rangeValue {
			return 0, fmt.Errorf("%w: constrained offset %d exceeds range [%d..%d]", ErrInvalidValue, val, lb, ub)
		}
		return addNonNegativeOffset(lb, val)
	}
}

// EncodeUnconstrainedLengthAligned encodes an unconstrained length determinant (APER).
// The length determinant is octet-aligned. X.691 Section 11.9.
func EncodeUnconstrainedLengthAligned(bb *BitBuffer, n int64) error {
	bb.AlignToOctetWrite()
	return EncodeUnconstrainedLength(bb, n)
}

// DecodeUnconstrainedLengthAligned decodes an unconstrained length determinant (APER).
func DecodeUnconstrainedLengthAligned(bb *BitBuffer) (int64, error) {
	bb.AlignToOctetRead()
	return DecodeUnconstrainedLength(bb)
}

// EncodeSemiConstrainedWholeNumberAligned encodes v with known lb, no ub (APER).
func EncodeSemiConstrainedWholeNumberAligned(bb *BitBuffer, v, lb int64) error {
	if v < lb {
		return fmt.Errorf("%w: %d below lower bound %d", ErrConstraintViolation, v, lb)
	}
	buf := minimalUnsignedBytes(uint64(v) - uint64(lb))
	if err := EncodeUnconstrainedLengthAligned(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

// DecodeSemiConstrainedWholeNumberAligned decodes a semi-constrained value (APER).
func DecodeSemiConstrainedWholeNumberAligned(bb *BitBuffer, lb int64) (int64, error) {
	length, err := DecodeUnconstrainedLengthAligned(bb)
	if err != nil {
		return 0, err
	}
	if length == 0 {
		return lb, nil
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
	return addNonNegativeOffset(lb, val)
}

// EncodeUnconstrainedWholeNumberAligned encodes a signed integer with no bounds (APER).
func EncodeUnconstrainedWholeNumberAligned(bb *BitBuffer, v int64) error {
	var buf []byte
	if v >= 0 {
		if v == 0 {
			buf = []byte{0}
		} else {
			buf = minimalUnsignedBytes(uint64(v))
			if buf[0]&0x80 != 0 {
				buf = append([]byte{0}, buf...)
			}
		}
	} else {
		buf = minimalSignedNegBytes(v)
	}
	if err := EncodeUnconstrainedLengthAligned(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

// DecodeUnconstrainedWholeNumberAligned decodes an unconstrained signed integer (APER).
func DecodeUnconstrainedWholeNumberAligned(bb *BitBuffer) (int64, error) {
	length, err := DecodeUnconstrainedLengthAligned(bb)
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

// EncodeNormallySmallNonNegativeAligned encodes a normally small non-negative number (APER).
func EncodeNormallySmallNonNegativeAligned(bb *BitBuffer, v int64) error {
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
	return EncodeSemiConstrainedWholeNumberAligned(bb, v, 0)
}

// DecodeNormallySmallNonNegativeAligned decodes a normally small non-negative number (APER).
func DecodeNormallySmallNonNegativeAligned(bb *BitBuffer) (int64, error) {
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
	return DecodeSemiConstrainedWholeNumberAligned(bb, 0)
}

// DecodeExtensionBitmapAligned decodes an aligned extension presence bitmap.
func DecodeExtensionBitmapAligned(bb *BitBuffer) (int64, []bool, error) {
	count, err := DecodeNormallySmallNonNegativeAligned(bb)
	if err != nil {
		return 0, nil, err
	}
	return decodeExtensionBitmapBits(bb, count)
}

// EncodeIntegerAligned encodes an integer using APER rules.
func EncodeIntegerAligned(bb *BitBuffer, v int64, lb, ub *int64, extensible bool) error {
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
			return EncodeUnconstrainedWholeNumberAligned(bb, v)
		}
	}
	if lb != nil && ub != nil {
		return EncodeConstrainedWholeNumberAligned(bb, v, *lb, *ub)
	}
	if lb != nil {
		return EncodeSemiConstrainedWholeNumberAligned(bb, v, *lb)
	}
	return EncodeUnconstrainedWholeNumberAligned(bb, v)
}

// DecodeIntegerAligned decodes an integer using APER rules.
func DecodeIntegerAligned(bb *BitBuffer, lb, ub *int64, extensible bool) (int64, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			return DecodeUnconstrainedWholeNumberAligned(bb)
		}
	}
	if lb != nil && ub != nil {
		return DecodeConstrainedWholeNumberAligned(bb, *lb, *ub)
	}
	if lb != nil {
		return DecodeSemiConstrainedWholeNumberAligned(bb, *lb)
	}
	return DecodeUnconstrainedWholeNumberAligned(bb)
}

// EncodeEnumeratedAligned encodes an enumerated value using APER rules.
func EncodeEnumeratedAligned(bb *BitBuffer, v int64, rootCount int, extensible bool) error {
	if extensible {
		isExtension := v >= int64(rootCount)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			return EncodeNormallySmallNonNegativeAligned(bb, v-int64(rootCount))
		}
	}
	if rootCount <= 1 {
		return nil
	}
	return EncodeConstrainedWholeNumberAligned(bb, v, 0, int64(rootCount-1))
}

// DecodeEnumeratedAligned decodes an enumerated value using APER rules.
func DecodeEnumeratedAligned(bb *BitBuffer, rootCount int, extensible bool) (int64, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			extIdx, err := DecodeNormallySmallNonNegativeAligned(bb)
			if err != nil {
				return 0, err
			}
			return int64(rootCount) + extIdx, nil
		}
	}
	if rootCount <= 1 {
		return 0, nil
	}
	return DecodeConstrainedWholeNumberAligned(bb, 0, int64(rootCount-1))
}

// EncodeBitStringAligned encodes a BIT STRING using APER rules.
func EncodeBitStringAligned(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained bool) error {
	return EncodeBitStringAlignedExt(bb, data, bitLen, lb, ub, constrained, false)
}

// EncodeBitStringAlignedExt encodes a BIT STRING with optional SIZE extensibility.
func EncodeBitStringAlignedExt(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained, extensible bool) error {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return err
	}
	if extensible && constrained {
		inRoot := int64(bitLen) >= lb && int64(bitLen) <= ub
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeLengthDelimitedBits(bb, data, bitLen, true)
		}
	}
	if err := validateRootSize(int64(bitLen), lb, ub, constrained); err != nil {
		return err
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		// Fixed size.
		if int64(bitLen) != lb {
			return fmt.Errorf("%w: BIT STRING length %d does not match fixed SIZE(%d)", ErrConstraintViolation, bitLen, lb)
		}
		if lb > 16 {
			bb.AlignToOctetWrite()
		}
		return bb.WriteBitsFromBytes(data, int(lb))
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumberAligned(bb, int64(bitLen), lb, ub); err != nil {
			return err
		}
		if ub > 16 {
			bb.AlignToOctetWrite()
		}
		return bb.WriteBitsFromBytes(data, bitLen)
	}
	return encodeLengthDelimitedBits(bb, data, bitLen, true)
}

// DecodeBitStringAligned decodes a BIT STRING using APER rules.
func DecodeBitStringAligned(bb *BitBuffer, lb, ub int64, constrained bool) ([]byte, int, error) {
	return DecodeBitStringAlignedExt(bb, lb, ub, constrained, false)
}

// DecodeBitStringAlignedExt decodes a BIT STRING with optional SIZE extensibility.
func DecodeBitStringAlignedExt(bb *BitBuffer, lb, ub int64, constrained, extensible bool) ([]byte, int, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return nil, 0, err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return nil, 0, err
		}
		if isExtension {
			return decodeLengthDelimitedBits(bb, true)
		}
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		if lb > 16 {
			bb.AlignToOctetRead()
		}
		data, err := bb.ReadBitsToBytes(int(lb))
		return data, int(lb), err
	}
	var bitLen int64
	var err error
	if constrained && ub < 65536 {
		bitLen, err = DecodeConstrainedWholeNumberAligned(bb, lb, ub)
		if err != nil {
			return nil, 0, err
		}
		if ub > 16 {
			bb.AlignToOctetRead()
		}
	} else {
		data, decodedLength, err := decodeLengthDelimitedBitsBounded(bb, true, rootSizeMaximum(ub, constrained))
		if err == nil {
			err = validateRootSize(int64(decodedLength), lb, ub, constrained)
		}
		return data, decodedLength, err
	}
	if err := validateRootSize(bitLen, lb, ub, constrained); err != nil {
		return nil, 0, err
	}
	data, err := bb.ReadBitsToBytes(int(bitLen))
	return data, int(bitLen), err
}

// EncodeOctetStringAligned encodes an OCTET STRING using APER rules.
func EncodeOctetStringAligned(bb *BitBuffer, data []byte, lb, ub int64, constrained bool) error {
	return EncodeOctetStringAlignedExt(bb, data, lb, ub, constrained, false)
}

// EncodeOctetStringAlignedExt encodes an OCTET STRING with optional SIZE extensibility.
func EncodeOctetStringAlignedExt(bb *BitBuffer, data []byte, lb, ub int64, constrained, extensible bool) error {
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
			return encodeLengthDelimitedOctets(bb, data, true)
		}
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return err
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		// Fixed size.
		if int64(len(data)) != lb {
			return fmt.Errorf("%w: OCTET STRING length %d does not match fixed SIZE(%d)", ErrConstraintViolation, len(data), lb)
		}
		if lb > 2 {
			bb.AlignToOctetWrite()
		}
		return bb.WriteBytes(data)
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumberAligned(bb, length, lb, ub); err != nil {
			return err
		}
		if ub > 2 {
			bb.AlignToOctetWrite()
		}
		return bb.WriteBytes(data)
	}
	return encodeLengthDelimitedOctets(bb, data, true)
}

// DecodeOctetStringAligned decodes an OCTET STRING using APER rules.
func DecodeOctetStringAligned(bb *BitBuffer, lb, ub int64, constrained bool) ([]byte, error) {
	return DecodeOctetStringAlignedExt(bb, lb, ub, constrained, false)
}

// DecodeOctetStringAlignedExt decodes an OCTET STRING with optional SIZE extensibility.
func DecodeOctetStringAlignedExt(bb *BitBuffer, lb, ub int64, constrained, extensible bool) ([]byte, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return nil, err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return nil, err
		}
		if isExtension {
			return decodeLengthDelimitedOctets(bb, true)
		}
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		if lb > 2 {
			bb.AlignToOctetRead()
		}
		return bb.ReadBytes(int(lb))
	}
	var length int64
	var err error
	if constrained && ub < 65536 {
		length, err = DecodeConstrainedWholeNumberAligned(bb, lb, ub)
		if err != nil {
			return nil, err
		}
		if ub > 2 {
			bb.AlignToOctetRead()
		}
	} else {
		data, err := decodeLengthDelimitedOctetsBounded(bb, true, rootSizeMaximum(ub, constrained))
		if err == nil {
			err = validateRootSize(int64(len(data)), lb, ub, constrained)
		}
		return data, err
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return nil, err
	}
	return bb.ReadBytes(int(length))
}

// EncodeKnownMultiplierStringAligned encodes a string with known char set (APER).
func EncodeKnownMultiplierStringAligned(bb *BitBuffer, s string, bitsPerChar int, lb, ub int64, constrained bool) error {
	return EncodeKnownMultiplierStringAlignedExt(bb, s, bitsPerChar, lb, ub, constrained, false)
}

// EncodeKnownMultiplierStringAlignedExt implements the size extension bit
// required by ITU-T X.691 (02/2021) Section 30.4.
func EncodeKnownMultiplierStringAlignedExt(bb *BitBuffer, s string, bitsPerChar int, lb, ub int64, constrained, extensible bool) error {
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
			return encodeLengthDelimitedKnownMultiplierString(bb, s, bitsPerChar, true)
		}
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return err
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		if length != lb {
			return fmt.Errorf("%w: string length %d does not match fixed SIZE(%d)", ErrConstraintViolation, length, lb)
		}
		payloadBits, err := knownMultiplierPayloadBits(length, bitsPerChar)
		if err != nil {
			return err
		}
		if payloadBits > 16 {
			bb.AlignToOctetWrite()
		}
		return writeKnownMultiplierString(bb, s, bitsPerChar)
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumberAligned(bb, length, lb, ub); err != nil {
			return err
		}
		if ub > 2 {
			bb.AlignToOctetWrite()
		}
	} else {
		return encodeLengthDelimitedKnownMultiplierString(bb, s, bitsPerChar, true)
	}
	return writeKnownMultiplierString(bb, s, bitsPerChar)
}

// DecodeKnownMultiplierStringAligned decodes a string with known char set (APER).
func DecodeKnownMultiplierStringAligned(bb *BitBuffer, bitsPerChar int, lb, ub int64, constrained bool) (string, error) {
	return DecodeKnownMultiplierStringAlignedExt(bb, bitsPerChar, lb, ub, constrained, false)
}

// DecodeKnownMultiplierStringAlignedExt implements the size extension bit
// required by ITU-T X.691 (02/2021) Section 30.4.
func DecodeKnownMultiplierStringAlignedExt(bb *BitBuffer, bitsPerChar int, lb, ub int64, constrained, extensible bool) (string, error) {
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
			value, _, err := decodeLengthDelimitedKnownMultiplierString(bb, bitsPerChar, true)
			return value, err
		}
	}
	var length int64
	var err error
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		payloadBits, payloadErr := knownMultiplierPayloadBits(lb, bitsPerChar)
		if payloadErr != nil {
			return "", payloadErr
		}
		if payloadBits > 16 {
			bb.AlignToOctetRead()
		}
		length = lb
	} else if constrained && ub < 65536 {
		length, err = DecodeConstrainedWholeNumberAligned(bb, lb, ub)
		if err != nil {
			return "", err
		}
		if ub > 2 {
			bb.AlignToOctetRead()
		}
	} else {
		value, decodedLength, err := decodeLengthDelimitedKnownMultiplierStringBounded(bb, bitsPerChar, true, rootSizeMaximum(ub, constrained))
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

// EncodeOpenTypeAligned wraps encoded bytes with an aligned length determinant (APER).
func EncodeOpenTypeAligned(bb *BitBuffer, data []byte) error {
	return encodeLengthDelimitedOctets(bb, data, true)
}

// DecodeOpenTypeAligned decodes an open type value (APER).
func DecodeOpenTypeAligned(bb *BitBuffer) ([]byte, error) {
	return decodeLengthDelimitedOctets(bb, true)
}

// EncodeChoiceIndexAligned encodes a CHOICE index (APER).
func EncodeChoiceIndexAligned(bb *BitBuffer, index int64, numAlternatives int, extensible bool) error {
	if extensible {
		isExtension := index >= int64(numAlternatives)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			return EncodeNormallySmallNonNegativeAligned(bb, index-int64(numAlternatives))
		}
	}
	if numAlternatives <= 1 {
		return nil
	}
	return EncodeConstrainedWholeNumberAligned(bb, index, 0, int64(numAlternatives-1))
}

// DecodeChoiceIndexAligned decodes a CHOICE index (APER).
func DecodeChoiceIndexAligned(bb *BitBuffer, numAlternatives int, extensible bool) (int64, bool, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, false, err
		}
		if isExtension {
			idx, err := DecodeNormallySmallNonNegativeAligned(bb)
			if err != nil {
				return 0, true, err
			}
			return int64(numAlternatives) + idx, true, nil
		}
	}
	if numAlternatives <= 1 {
		return 0, false, nil
	}
	idx, err := DecodeConstrainedWholeNumberAligned(bb, 0, int64(numAlternatives-1))
	return idx, false, err
}
