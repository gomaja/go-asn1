// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/aper.go; SHA-256 4e3bf1539254d936365c97a1c6f509643102fb2519e83a730d879e0320553570.
package aper

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// EncodeConstrainedWholeNumberAligned encodes v in [lb..ub] using APER rules.
// ITU-T X.691 (02/2021), clauses 11.5.6-11.5.7.
func EncodeConstrainedWholeNumberAligned(bb *BitBuffer, v, lb, ub int64) error {
	if err := bb.ChargeAllocation(1, 16); err != nil {
		return err
	}
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
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
		}
		return bb.WriteBits(offset, 8)
	case rangeValue < 65536:
		// 257..65536 values: 16-bit field, octet-aligned.
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
		}
		return bb.WriteBits(offset, 16)
	default:
		// Range > 65535: length-determinant (NOT aligned) + value bytes (octet-aligned).
		// The length determinant precedes octet alignment of the value.
		var n int
		n, err := octetsForBitLength(bits.Len64(offset))
		if err != nil {
			return err
		}
		if n == 0 {
			n = 1
		}
		// Length determinant: number of bytes needed, encoded as constrained [1..maxBytes].
		var maxBytes int
		maxBytes, err = octetsForBitLength(bits.Len64(rangeValue))
		if err != nil {
			return err
		}
		if err := EncodeConstrainedWholeNumber(bb, int64(n), 1, int64(maxBytes)); err != nil {
			return err
		}
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
		}
		for i := n; i > 0; {
			i--
			if i >= 8 {
				return fmt.Errorf("%w: constrained INTEGER octet index %d", ErrInvalidValue, i)
			}
			if err := bb.WriteBits((offset>>(uint(i)*8))&0xFF, 8); err != nil {
				return err
			}
		}
		return nil
	}
}

// DecodeConstrainedWholeNumberAligned decodes a value from [lb..ub] using APER rules.
func DecodeConstrainedWholeNumberAligned(bb *BitBuffer, lb, ub int64) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, constrainedWholeClause(lb, ub), &result1)

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
			return 0, int64OffsetError(offset, lb, ub)
		}
		return addNonNegativeOffset(lb, offset)
	case rangeValue == 255:
		// Exactly 256 values: 8-bit field, octet-aligned.
		if err := bb.AlignToOctetRead(); err != nil {
			return 0, err
		}
		offset, err := bb.ReadBits(8)
		if err != nil {
			return 0, err
		}
		return addNonNegativeOffset(lb, offset)
	case rangeValue < 65536:
		if err := bb.AlignToOctetRead(); err != nil {
			return 0, err
		}
		offset, err := bb.ReadBits(16)
		if err != nil {
			return 0, err
		}
		if offset > rangeValue {
			return 0, int64OffsetError(offset, lb, ub)
		}
		return addNonNegativeOffset(lb, offset)
	default:
		// Range > 65535: length-determinant (NOT aligned) + value bytes (octet-aligned).
		// The length determinant precedes octet alignment of the value.
		var maxBytes int
		maxBytes, err := octetsForBitLength(bits.Len64(rangeValue))
		if err != nil {
			return 0, err
		}
		n, err := DecodeConstrainedWholeNumber(bb, 1, int64(maxBytes))
		if err != nil {
			return 0, err
		}
		if n >= 1 && n <= 8 {
			if err := bb.AlignToOctetRead(); err != nil {
				return 0, err
			}
			var data []byte
			data, err = bb.ReadBytes(int(n))
			if err != nil {
				return 0, err
			}
			// ITU-T X.691 (02/2021) §§11.3.6, 11.5.7.4.
			if err := validateMinimalUnsigned(data); err != nil {
				return 0, err
			}
			var val uint64
			for _, b := range data {
				if val > math.MaxUint64>>8 {
					return 0, fmt.Errorf("%w: constrained INTEGER exceeds uint64", ErrInvalidValue)
				}
				val = (val << 8) | uint64(b)
			}
			if val > rangeValue {
				return 0, int64OffsetError(val, lb, ub)
			}
			return addNonNegativeOffset(lb, val)
		}
		return 0, fmt.Errorf("%w: constrained INTEGER length %d is outside [1..8]", ErrInvalidValue, n)
	}
}

// EncodeUnconstrainedLengthAligned encodes an unconstrained length determinant (APER).
// The length determinant is octet-aligned. X.691 Section 11.9.
func EncodeUnconstrainedLengthAligned(bb *BitBuffer, n int64) error {
	if err := bb.AlignToOctetWrite(); err != nil {
		return err
	}
	return EncodeUnconstrainedLength(bb, n)
}

// DecodeUnconstrainedLengthAligned decodes an unconstrained length determinant (APER).
func DecodeUnconstrainedLengthAligned(bb *BitBuffer) (int64, error) {
	if err := bb.AlignToOctetRead(); err != nil {
		return 0, err
	}
	return DecodeUnconstrainedLength(bb)
}

// EncodeSemiConstrainedWholeNumberAligned encodes v with known lb, no ub (APER).
func EncodeSemiConstrainedWholeNumberAligned(bb *BitBuffer, v, lb int64) error {
	if err := bb.ChargeAllocation(1, 16); err != nil {
		return err
	}
	if v < lb {
		return fmt.Errorf("%w: %d below lower bound %d", ErrConstraintViolation, v, lb)
	}
	buf := minimalUnsignedBytes(uint64(v) - uint64(lb))
	if len(buf) > math.MaxInt/8 {
		return fmt.Errorf("%w: semi-constrained INTEGER exceeds bit-buffer capacity", ErrInvalidValue)
	}
	if err := EncodeUnconstrainedLengthAligned(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

// DecodeSemiConstrainedWholeNumberAligned decodes a semi-constrained value (APER).
func DecodeSemiConstrainedWholeNumberAligned(bb *BitBuffer, lb int64) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.7.4", &result1)

	var data []byte
	data, err := decodeIntegerContentsAligned(bb)
	if err != nil {
		return 0, err
	}
	// ITU-T X.691 (02/2021) §§11.3.6, 11.7.4 require minimum octets.
	if err := validateMinimalUnsigned(data); err != nil {
		return 0, err
	}
	// X.691 (02/2021) §§11.3.6, 11.7.4: inspect minimal contents
	// before applying the operational uint64/int64 carrier boundaries.
	if len(data) > 8 {
		return 0, bb.resourceError("non-negative integer representation maximum is 8 octets")
	}
	var val uint64
	for _, b := range data {
		if val > math.MaxUint64>>8 {
			return 0, fmt.Errorf("%w: semi-constrained INTEGER exceeds uint64", ErrInvalidValue)
		}
		val = (val << 8) | uint64(b)
	}
	value, err := addNonNegativeOffset(lb, val)
	if err != nil {
		return 0, bb.resourceError("semi-constrained INTEGER exceeds int64 representation")
	}
	return value, nil
}

// EncodeUnconstrainedWholeNumberAligned encodes a signed integer with no bounds (APER).
func EncodeUnconstrainedWholeNumberAligned(bb *BitBuffer, v int64) error {
	if err := bb.ChargeAllocation(1, 24); err != nil {
		return err
	}
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
	// X.691 (02/2021) §11.8 permits values outside int64.
	value, err := decodeBigTwosComplement(bb, true)
	if err != nil {
		return 0, err
	}
	if !value.IsInt64() {
		return 0, bb.resourceError("unconstrained INTEGER exceeds int64 representation")
	}
	return value.Int64(), nil
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
func DecodeNormallySmallNonNegativeAligned(bb *BitBuffer) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.6.2", &result1)

	bit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		val, err := bb.ReadBits(6)
		if err != nil {
			return 0, err
		}
		if val > 63 {
			return 0, fmt.Errorf("%w: normally small INTEGER exceeds six bits", ErrInvalidValue)
		}
		return int64(val), nil
	}
	value, err := DecodeSemiConstrainedWholeNumberAligned(bb, 0)
	if err != nil {
		return 0, err
	}
	// ITU-T X.691 (02/2021) §11.6.1-11.6.2 requires the short form below 64.
	if value < 64 {
		return 0, fmt.Errorf("%w: long normally small INTEGER %d is below 64", ErrInvalidValue, value)
	}
	return value, nil
}

// EncodeNormallySmallLengthAligned encodes a positive normally small length.
// ITU-T X.691 (02/2021) 11.9.3.4 and 19.8.
func EncodeNormallySmallLengthAligned(bb *BitBuffer, n int64) error {
	if n < 1 {
		return fmt.Errorf("%w: normally small length %d is not positive", ErrInvalidValue, n)
	}
	if n >= 16384 {
		return bb.unsupportedBitmapLength(fmt.Sprintf("length %d is not below 16384", n))
	}
	if n <= 64 {
		if err := bb.WriteBit(0); err != nil {
			return err
		}
		return bb.WriteBits(uint64(n-1), 6)
	}
	if err := bb.WriteBit(1); err != nil {
		return err
	}
	return EncodeUnconstrainedLengthAligned(bb, n)
}

// DecodeNormallySmallLengthAligned decodes a positive normally small length.
// ITU-T X.691 (02/2021) 11.9.3.4 and 19.8.
func DecodeNormallySmallLengthAligned(bb *BitBuffer) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.9.3.4", &result1)

	bit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		value, err := bb.ReadBits(6)
		return int64(value) + 1, err
	}
	n, more, _, err := decodeLengthFragmentDeterminant(bb, true)
	if err != nil {
		return 0, err
	}
	if more {
		return 0, bb.unsupportedBitmapLength(fmt.Sprintf("first fragment length %d", n))
	}
	if n <= 64 {
		return 0, fmt.Errorf("%w: long normally small length %d is not greater than 64", ErrInvalidValue, n)
	}
	return n, nil
}

// DecodeExtensionBitmapAligned decodes an aligned extension presence bitmap.
func DecodeExtensionBitmapAligned(bb *BitBuffer) (int64, []bool, error) {
	n, err := DecodeNormallySmallLengthAligned(bb)
	if err != nil {
		return 0, nil, err
	}
	return decodeExtensionBitmapBits(bb, n-1)
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
	// X.691 (02/2021) 13.2.4: with only an upper bound the value is an
	// unconstrained whole number, which can carry a value above the bound.
	if err := checkIntegerUpperBound(v, ub); err != nil {
		return err
	}
	return EncodeUnconstrainedWholeNumberAligned(bb, v)
}

// DecodeIntegerAligned decodes an integer using APER rules.
func DecodeIntegerAligned(bb *BitBuffer, lb, ub *int64, extensible bool) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, integerClause(lb, ub, extensible), &result1)

	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			value, err := DecodeUnconstrainedWholeNumberAligned(bb)
			if err == nil {
				err = rejectRootValueInExtension(value, integerInRoot(value, lb, ub))
			}
			return value, err
		}
	}
	if lb != nil && ub != nil {
		return DecodeConstrainedWholeNumberAligned(bb, *lb, *ub)
	}
	if lb != nil {
		return DecodeSemiConstrainedWholeNumberAligned(bb, *lb)
	}
	value, err := DecodeUnconstrainedWholeNumberAligned(bb)
	if err == nil {
		err = checkIntegerUpperBound(value, ub)
	}
	return value, err
}

// EncodeEnumeratedAligned encodes an enumerated value using APER rules.
func EncodeEnumeratedAligned(bb *BitBuffer, v int64, rootCount int, extensible bool) error {
	// X.680 (02/2021) §20.1 requires a root EnumerationItem; X.691
	// (02/2021) §§14.2, 13.2.1 omit the index only for a singleton root.
	if rootCount <= 0 {
		return fmt.Errorf("%w: nonpositive ENUMERATED root count %d", ErrInvalidValue, rootCount)
	}
	if v < 0 || !extensible && v >= int64(rootCount) {
		return fmt.Errorf("%w: ENUMERATED index %d outside %d root values", ErrInvalidValue, v, rootCount)
	}
	if extensible {
		isExtension := v >= int64(rootCount)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			if v < int64(rootCount) {
				return fmt.Errorf("%w: ENUMERATED extension index below root", ErrInvalidValue)
			}
			return EncodeNormallySmallNonNegativeAligned(bb, v-int64(rootCount))
		}
	}
	if rootCount <= 1 {
		return nil
	}
	return EncodeConstrainedWholeNumberAligned(bb, v, 0, int64(rootCount-1))
}

// DecodeEnumeratedAligned decodes an enumerated value using APER rules.
func DecodeEnumeratedAligned(bb *BitBuffer, rootCount int, extensible bool, source ...EnumerationSource) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	sourceClause := "§14.2"
	defer func() { bb.locateDecodeFailure(sourceStart, sourceClause, &result1) }()

	if rootCount <= 0 {
		return 0, fmt.Errorf("%w: nonpositive ENUMERATED root count %d", ErrInvalidValue, rootCount)
	}
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			sourceClause = "§14.3"
			extIdx, err := DecodeNormallySmallNonNegativeAligned(bb)
			if err != nil {
				return 0, err
			}
			if extIdx > math.MaxInt64-int64(rootCount) {
				return 0, bb.resourceError("enumerated extension exceeds int64 representation")
			}
			value, err := addExtensionIndex(rootCount, extIdx)
			if err != nil {
				return 0, err
			}
			info := EnumerationSource{}
			if len(source) != 0 {
				info = source[0]
			}
			if extIdx >= int64(info.KnownExtensions) {
				location := Location{Path: info.Path}
				if location.Path == "" {
					location.Path = "ENUMERATED"
				}
				location.Spans, location.HasWireLocation = originalRange(bb, uint64(sourceStart), uint64(bb.BitPos()))
				raw := OpaqueOpenType{parent: bb, origin: OpaqueOrigin{Location: location, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§14.3"}}}
				if err := raw.Observe(UnknownExtension); err != nil {
					return 0, err
				}
			}
			return value, nil
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
		if lb < 0 || lb > int64(math.MaxInt) {
			return fmt.Errorf("%w: BIT STRING length exceeds host int", ErrInvalidValue)
		}
		if lb > 16 {
			if err := bb.AlignToOctetWrite(); err != nil {
				return err
			}
		}
		return bb.WriteBitsFromBytes(data, int(lb))
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumberAligned(bb, int64(bitLen), lb, ub); err != nil {
			return err
		}
		// X.691 (02/2021) 16.11 octet-aligns every bitstring that is not
		// fixed-size, whatever "ub" is; 11.9.3.3 adds nothing, not even
		// padding, after a zero length.
		if bitLen == 0 {
			return nil
		}
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
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
func DecodeBitStringAlignedExt(bb *BitBuffer, lb, ub int64, constrained, extensible bool) (result0 []byte, result1 int, result2 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, bitStringClause(lb, ub, constrained, extensible), &result2)

	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return nil, 0, err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return nil, 0, err
		}
		if isExtension {
			data, bitLen, err := decodeLengthDelimitedBits(bb, true)
			if err == nil {
				err = rejectRootLengthInExtension("BIT STRING", int64(bitLen), lb, ub)
			}
			return data, bitLen, err
		}
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		if lb < 0 || lb > int64(math.MaxInt) {
			return nil, 0, fmt.Errorf("%w: BIT STRING length exceeds host int", ErrInvalidValue)
		}
		if lb > 16 {
			if err := bb.AlignToOctetRead(); err != nil {
				return nil, 0, err
			}
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
		// X.691 (02/2021) 16.11 and 11.9.3.3, as in EncodeBitStringAlignedExt.
		if bitLen != 0 {
			if err := bb.AlignToOctetRead(); err != nil {
				return nil, 0, err
			}
		}
	} else {
		var data []byte
		var decodedLength int
		data, decodedLength, err = decodeLengthDelimitedBitsBounded(bb, true, rootSizeMaximum(ub, constrained))
		if err == nil {
			err = validateRootSize(int64(decodedLength), lb, ub, constrained)
		}
		return data, decodedLength, err
	}
	if err := validateRootSize(bitLen, lb, ub, constrained); err != nil {
		return nil, 0, err
	}
	if bitLen < 0 || bitLen > int64(math.MaxInt) {
		return nil, 0, fmt.Errorf("%w: BIT STRING length exceeds host int", ErrInvalidValue)
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
			if err := bb.AlignToOctetWrite(); err != nil {
				return err
			}
		}
		return bb.WriteBytes(data)
	}
	if constrained && ub < 65536 {
		if err := EncodeConstrainedWholeNumberAligned(bb, length, lb, ub); err != nil {
			return err
		}
		// X.691 (02/2021) 17.8 octet-aligns every octetstring that is not
		// fixed-size, whatever "ub" is; 11.9.3.3 adds nothing, not even
		// padding, after a zero length.
		if length == 0 {
			return nil
		}
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
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
func DecodeOctetStringAlignedExt(bb *BitBuffer, lb, ub int64, constrained, extensible bool) (result0 []byte, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, octetStringClause(lb, ub, constrained, extensible), &result1)

	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return nil, err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return nil, err
		}
		if isExtension {
			data, err := decodeLengthDelimitedOctets(bb, true)
			if err == nil {
				err = rejectRootLengthInExtension("OCTET STRING", int64(len(data)), lb, ub)
			}
			return data, err
		}
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		if lb < 0 || lb > int64(math.MaxInt) {
			return nil, fmt.Errorf("%w: OCTET STRING length exceeds host int", ErrInvalidValue)
		}
		if lb > 2 {
			if err := bb.AlignToOctetRead(); err != nil {
				return nil, err
			}
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
		// X.691 (02/2021) 17.8 and 11.9.3.3, as in EncodeOctetStringAlignedExt.
		if length != 0 {
			if err := bb.AlignToOctetRead(); err != nil {
				return nil, err
			}
		}
	} else {
		var data []byte
		data, err = decodeLengthDelimitedOctetsBounded(bb, true, rootSizeMaximum(ub, constrained))
		if err == nil {
			err = validateRootSize(int64(len(data)), lb, ub, constrained)
		}
		return data, err
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return nil, err
	}
	if length < 0 || length > int64(math.MaxInt) {
		return nil, fmt.Errorf("%w: OCTET STRING length exceeds host int", ErrInvalidValue)
	}
	return bb.ReadBytes(int(length))
}

// EncodeOpenTypeAligned wraps a complete encoding with an aligned length
// determinant. ITU-T X.691 (02/2021), clause 11.2.
func EncodeOpenTypeAligned(bb *BitBuffer, data []byte) error {
	if uint64(len(data)) > bb.openTypeMaximum() {
		return bb.resourceError("open type bytes exceeded")
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: APER open type requires a complete encoding", ErrInvalidValue)
	}
	return encodeLengthDelimitedOctets(bb, data, true)
}

// DecodeOpenTypeAligned decodes an open type's complete encoding (APER).
func DecodeOpenTypeAligned(bb *BitBuffer) ([]byte, error) {
	return decodeOpenTypeAlignedObserved(bb, nil)
}

func decodeOpenTypeAlignedObserved(bb *BitBuffer, observe func(offset, length int64, bitStart int)) (result0 []byte, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.2.1", &result1)

	// X.691 (02/2021) §11.2.2 delimits each frame; account for it
	// even when the actual type is opaque. This is a receiver ceiling.
	if err := bb.EnterOpenType(); err != nil {
		return nil, err
	}
	defer bb.LeaveOpenType()
	data, err := decodeLengthDelimitedOctetsObserved(bb, true, int64(bb.openTypeMaximum()), observe)
	if err != nil {
		if errors.Is(err, ErrConstraintViolation) && bb.decodeBudget().operational.MaxOpenTypeBytes != 0 {
			return nil, bb.resourceError("open type bytes exceeded")
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, bb.syntaxError(bb.BitPos(), "§11.2.1", "APER open type has an empty complete encoding", ErrInvalidValue)
	}
	return data, nil
}

// EnumerationSource identifies the source-known extension indexes. X.691
// (02/2021) §§14.1 and 14.3 number extensions separately from root indexes.
type EnumerationSource struct {
	KnownExtensions int
	Path            Path
}

func (bb *BitBuffer) openTypeMaximum() uint64 {
	limit := bb.decodeBudget().operational.MaxOpenTypeBytes
	if limit == 0 {
		return math.MaxInt64
	}
	return limit
}

func (bb *BitBuffer) unsupportedBitmapLength(message string) error {
	if err := bb.decodeBudget().err; err != nil {
		return err
	}
	failure := bb.resourceError(message)
	if located, ok := failure.(*DecodeError); ok {
		located.Err = fmt.Errorf("%w: %s", ErrUnsupportedFragmentedNormallySmallLength, message)
	}
	return failure
}
