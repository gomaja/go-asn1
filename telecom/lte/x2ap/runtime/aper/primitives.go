// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/primitives.go; SHA-256 7c844e6bf856991df088f5d991f3ef1487be3fe3fe92dfd43b2293309c1659a2.
package aper

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
)

// EncodeBoolean encodes a boolean as 1 bit.
func EncodeBoolean(bb *BitBuffer, v bool) error {
	if v {
		return bb.WriteBit(1)
	}
	return bb.WriteBit(0)
}

// DecodeBoolean decodes a boolean from 1 bit.
func DecodeBoolean(bb *BitBuffer) (result0 bool, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§12", &result1)

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
func DecodeConstrainedWholeNumber(bb *BitBuffer, lb, ub int64) (result0 int64, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§11.5.6", &result1)

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
		return 0, int64OffsetError(offset, lb, ub)
	}
	return addNonNegativeOffset(lb, offset)
}

func decodeExtensionBitmapBits(bb *BitBuffer, count int64) (result0 int64, result1 []bool, result2 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§19.7", &result2)

	remaining := bb.BitsRemaining()
	if remaining < 0 {
		return 0, nil, fmt.Errorf("%w: negative remaining PER bits %d", ErrInvalidValue, remaining)
	}
	if count < 0 {
		return 0, nil, fmt.Errorf("%w: negative extension bitmap index %d", ErrInvalidValue, count)
	}
	// count is the highest index, so the bitmap contains count+1 bits.
	if count >= int64(remaining) {
		return 0, nil, fmt.Errorf("%w: extension bitmap index %d exceeds %d remaining bits", ErrTruncated, count, remaining)
	}
	if err := bb.ChargeAllocation(uint64(count)+1, 1); err != nil {
		return 0, nil, err
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
	return fmt.Errorf("per: length %d is not below 16384 and requires fragmentation (not yet supported)", n)
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

// X.691 (02/2021) §§14, 23 encode extension alternatives as a normally
// small index following the root alternatives. Reject indexes that the API's
// int64 representation cannot hold.
func addExtensionIndex(rootCount int, extensionIndex int64) (int64, error) {
	if rootCount < 0 || extensionIndex < 0 {
		return 0, fmt.Errorf("%w: extension index %d exceeds int64 range with %d root alternatives", ErrInvalidValue, extensionIndex, rootCount)
	}
	if extensionIndex > math.MaxInt64-int64(rootCount) {
		return 0, fmt.Errorf("%w: extension index %d exceeds int64 range with %d root alternatives", ErrInvalidValue, extensionIndex, rootCount)
	}
	return int64(rootCount) + extensionIndex, nil
}

func encodeLengthDelimitedBits(bb *BitBuffer, data []byte, bitLength int, aligned bool) error {
	required, err := octetsForBitLength(bitLength)
	if err != nil {
		return fmt.Errorf("BIT STRING length: %w", err)
	}
	if required > len(data) {
		return fmt.Errorf("%w: BIT STRING length %d bits requires %d octets, source has %d octets", ErrInvalidValue, bitLength, required, len(data))
	}
	return EncodeLengthFragments(bb, int64(bitLength), aligned, func(offset, length int64) error {

		if err := bb.AlignToOctetWrite(); err != nil {
			return err
		}

		if offset%8 != 0 {
			return fmt.Errorf("%w: BIT STRING fragment offset %d is not octet-aligned", ErrInvalidValue, offset)
		}
		if offset < 0 || length < 0 {
			return fmt.Errorf("%w: negative BIT STRING fragment offset %d bits or length %d bits", ErrInvalidValue, offset, length)
		}
		start := offset / 8
		if start > int64(len(data)) {
			return fmt.Errorf("%w: BIT STRING fragment starts at octet %d beyond %d source octets", ErrInvalidValue, start, len(data))
		}
		if length > int64(math.MaxInt) {
			return fmt.Errorf("%w: BIT STRING fragment length %d bits exceeds host int", ErrInvalidValue, length)
		}
		return bb.WriteBitsFromBytes(data[int(start):], int(length))
	})
}

func decodeLengthDelimitedBits(bb *BitBuffer, aligned bool) ([]byte, int, error) {
	return decodeLengthDelimitedBitsBounded(bb, aligned, math.MaxInt64)
}

func decodeLengthDelimitedBitsBounded(bb *BitBuffer, aligned bool, maximum int64) ([]byte, int, error) {
	result := []byte{} // present empty is not absent (go-asn1#91); no allocation
	total, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(offset int64, length int64) error {

		if err := bb.AlignToOctetRead(); err != nil {
			return err
		}

		remaining := bb.BitsRemaining()
		if remaining < 0 {
			return fmt.Errorf("%w: negative remaining PER bits %d", ErrInvalidValue, remaining)
		}
		if length < 0 || length > int64(remaining) || length > int64(math.MaxInt) {
			if offset > 0 || length >= perFragmentUnit {
				return bb.syntaxError(bb.BitPos(), "§11.9.3.8.2", "incomplete BIT STRING fragment contents", ErrTruncated)
			}
			return fmt.Errorf("%w: BIT STRING fragment requires %d bits with %d remaining", ErrTruncated, length, bb.BitsRemaining())
		}
		fragment, err := bb.ReadBitsToBytes(int(length))
		if err != nil {
			return err
		}
		result, err = AppendValues(bb, result, fragment...)
		if err != nil {
			return err
		}
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
	if lb >= 0 {
		return 0, fmt.Errorf("%w: non-negative offset %d overflows int64 lower bound %d", ErrInvalidValue, offset, lb)
	}
	absLowerBound := uint64(-(lb + 1)) + 1
	if offset < absLowerBound {
		return 0, fmt.Errorf("%w: offset %d below absolute lower bound %d", ErrInvalidValue, offset, absLowerBound)
	}
	delta := offset - absLowerBound
	if delta > math.MaxInt64 {
		return 0, fmt.Errorf("%w: offset %d exceeds int64", ErrInvalidValue, offset)
	}
	return int64(delta), nil
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

// integerInRoot reports whether value lies in the extension root of an
// INTEGER with the given bounds; a nil bound is unset.
func integerInRoot(value int64, lb, ub *int64) bool {
	return (lb == nil || value >= *lb) && (ub == nil || value <= *ub)
}

// checkIntegerUpperBound rejects a value above an INTEGER's upper bound that
// an unconstrained whole number carried, as the big-integer codecs do. In an
// extensible type such a value is outside the root, and 13.1 sends it in
// extension form.
func checkIntegerUpperBound(value int64, ub *int64) error {
	if ub != nil && value > *ub {
		return fmt.Errorf("%w: INTEGER %d above upper bound %d", ErrConstraintViolation, value, *ub)
	}
	return nil
}

// rejectRootValueInExtension enforces X.691 (02/2021) 13.1: the extension bit
// of an INTEGER is 1 only for a value outside the extension root, so a root
// value in extension form is not an encoding of that value and cannot be
// re-encoded as received.
func rejectRootValueInExtension[T int64 | uint64 | *big.Int](value T, inRoot bool) error {
	if inRoot {
		return fmt.Errorf("%w: extension INTEGER value %v is inside the extension root", ErrInvalidValue, value)
	}
	return nil
}

// rejectRootLengthInExtension enforces X.691 (02/2021) 16.6 and 17.3: the
// extension bit marks only a length outside the root, so a root length in
// extension form cannot be re-encoded as received.
func rejectRootLengthInExtension(what string, length, lb, ub int64) error {
	if length >= lb && length <= ub {
		return fmt.Errorf("%w: extension %s length %d is inside the root SIZE(%d..%d)", ErrInvalidValue, what, length, lb, ub)
	}
	return nil
}

func rootSizeMaximum(ub int64, constrained bool) int64 {
	if constrained {
		return ub
	}
	return math.MaxInt64
}

// X.691 (02/2021) 16.10 omits the length only for fixed sizes below
// 64K; 16.11 requires a length determinant at 64K and above.
func fixedRootSizeOmitsLength(lb, ub int64, constrained bool) bool {
	return constrained && lb == ub && ub < 64*1024
}

func minimalUnsignedBytes(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	width := bits.Len64(v)
	if width < 1 || width > 64 {
		return []byte{0}
	}
	n := (width + 7) / 8
	buf := make([]byte, n)
	for i := n; i > 0; {
		i--
		buf[i] = byte(v & 0xff)
		v >>= 8
	}
	return buf
}

func minimalSignedNegBytes(v int64) []byte {
	// Encode negative v as minimal 2's complement.
	if v >= 0 {
		return nil
	}
	uv := uint64(v)
	// Find minimal byte count: start from 1 and check sign extension.
	for n := 1; n <= 8; {
		// Check if n bytes can represent v.
		shift := uint(n * 8)
		if shift < 8 || shift > 64 {
			return nil
		}
		if n == 8 || (int64(uv<<(64-shift))>>(64-shift)) == v {
			buf := make([]byte, n)
			for i := n; i > 0; {
				i--
				buf[i] = byte(uv & 0xff)
				uv >>= 8
			}
			return buf
		}
		n++
	}
	return nil
}
