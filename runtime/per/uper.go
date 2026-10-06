package per

import (
	"fmt"
	"math"
	"math/bits"
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
		return 0, int64OffsetError(offset, lb, ub)
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
		if val > 63 {
			return 0, fmt.Errorf("%w: normally small INTEGER exceeds six bits", ErrInvalidValue)
		}
		return int64(val), nil
	}
	value, err := DecodeSemiConstrainedWholeNumber(bb, 0)
	if err != nil {
		return 0, err
	}
	// ITU-T X.691 (02/2021) §11.6.1-11.6.2 requires the short form below 64.
	if value < 64 {
		return 0, fmt.Errorf("%w: long normally small INTEGER %d is below 64", ErrInvalidValue, value)
	}
	return value, nil
}

// EncodeNormallySmallLength encodes a positive normally small length.
// ITU-T X.691 (02/2021) 11.9.3.4 encodes n-1 only for n <= 64;
// larger lengths use the unconstrained length determinant for n itself.
func EncodeNormallySmallLength(bb *BitBuffer, n int64) error {
	if n < 1 {
		return fmt.Errorf("%w: normally small length %d is not positive", ErrInvalidValue, n)
	}
	if n >= 16384 {
		return fmt.Errorf("%w: length %d is not below 16384", ErrUnsupportedFragmentedNormallySmallLength, n)
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
	return EncodeUnconstrainedLength(bb, n)
}

// DecodeNormallySmallLength decodes a positive normally small length.
// ITU-T X.691 (02/2021) 11.9.3.4.
func DecodeNormallySmallLength(bb *BitBuffer) (int64, error) {
	bit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		value, err := bb.ReadBits(6)
		return int64(value) + 1, err
	}
	n, more, _, err := decodeLengthFragmentDeterminant(bb, false)
	if err != nil {
		return 0, err
	}
	if more {
		return 0, fmt.Errorf("%w: first fragment length %d", ErrUnsupportedFragmentedNormallySmallLength, n)
	}
	if n <= 64 {
		return 0, fmt.Errorf("%w: long normally small length %d is not greater than 64", ErrInvalidValue, n)
	}
	return n, nil
}

// DecodeExtensionBitmap decodes the highest extension index and presence bits.
func DecodeExtensionBitmap(bb *BitBuffer) (int64, []bool, error) {
	n, err := DecodeNormallySmallLength(bb)
	if err != nil {
		return 0, nil, err
	}
	return decodeExtensionBitmapBits(bb, n-1)
}

func decodeExtensionBitmapBits(bb *BitBuffer, count int64) (int64, []bool, error) {
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
	// X.691 (02/2021) §11.8 permits values outside int64. Decode through
	// the arbitrary-precision path before applying this API's range limit.
	value, err := decodeBigTwosComplement(bb, false)
	if err != nil {
		return 0, err
	}
	if !value.IsInt64() {
		return 0, fmt.Errorf("%w: unconstrained INTEGER %s exceeds int64", ErrInvalidValue, value)
	}
	return value.Int64(), nil
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
	if rootCount <= 0 {
		return 0, fmt.Errorf("%w: nonpositive ENUMERATED root count %d", ErrInvalidValue, rootCount)
	}
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
			return addExtensionIndex(rootCount, extIdx)
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
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		// Fixed size — write exactly lb bits.
		if int64(bitLen) != lb {
			return fmt.Errorf("%w: BIT STRING length %d does not match fixed SIZE(%d)", ErrConstraintViolation, bitLen, lb)
		}
		if lb < 0 || lb > int64(math.MaxInt) {
			return fmt.Errorf("%w: BIT STRING length exceeds host int", ErrInvalidValue)
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
			data, bitLen, err := decodeLengthDelimitedBits(bb, false)
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
	if bitLen < 0 || bitLen > int64(math.MaxInt) {
		return nil, 0, fmt.Errorf("%w: BIT STRING length exceeds host int", ErrInvalidValue)
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
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
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
			data, err := decodeLengthDelimitedOctets(bb, false)
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
	if length < 0 || length > int64(math.MaxInt) {
		return nil, fmt.Errorf("%w: OCTET STRING length exceeds host int", ErrInvalidValue)
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

// EncodeKnownMultiplierString encodes a known-multiplier character string of
// a type's whole alphabet whose character values all fit in alphabetBits, B
// of ITU-T X.691 (02/2021) 30.5.2: 7 for IA5String, VisibleString and
// PrintableString, 16 for BMPString and 32 for UniversalString. Each
// character encodes as its own value (30.5.4 a)). NumericString, and any
// type with a PER-visible permitted-alphabet constraint, use
// EncodeAlphabetString instead.
func EncodeKnownMultiplierString(bb *BitBuffer, s string, alphabetBits int, lb, ub int64, constrained bool) error {
	return EncodeKnownMultiplierStringExt(bb, s, alphabetBits, lb, ub, constrained, false)
}

// EncodeKnownMultiplierStringExt implements the size extension bit required
// by ITU-T X.691 (02/2021) Section 30.4.
func EncodeKnownMultiplierStringExt(bb *BitBuffer, s string, alphabetBits int, lb, ub int64, constrained, extensible bool) error {
	codec, err := identityCharacterCodec(alphabetBits, false)
	if err != nil {
		return err
	}
	return encodeCharacterString(bb, s, codec, lb, ub, constrained, extensible, false)
}

// DecodeKnownMultiplierString decodes a string encoded by
// EncodeKnownMultiplierString.
func DecodeKnownMultiplierString(bb *BitBuffer, alphabetBits int, lb, ub int64, constrained bool) (string, error) {
	return DecodeKnownMultiplierStringExt(bb, alphabetBits, lb, ub, constrained, false)
}

// DecodeKnownMultiplierStringExt implements the size extension bit required
// by ITU-T X.691 (02/2021) Section 30.4.
func DecodeKnownMultiplierStringExt(bb *BitBuffer, alphabetBits int, lb, ub int64, constrained, extensible bool) (string, error) {
	codec, err := identityCharacterCodec(alphabetBits, false)
	if err != nil {
		return "", err
	}
	return decodeCharacterString(bb, codec, lb, ub, constrained, extensible, false)
}

// EncodeOpenType wraps a complete encoding with an unconstrained length
// determinant. ITU-T X.691 (02/2021), clause 11.2.
func EncodeOpenType(bb *BitBuffer, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: UPER open type requires a complete encoding", ErrInvalidValue)
	}
	return encodeLengthDelimitedOctets(bb, data, false)
}

// DecodeOpenType decodes an open type's complete encoding.
func DecodeOpenType(bb *BitBuffer) ([]byte, error) {
	data, err := decodeLengthDelimitedOctets(bb, false)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: UPER open type has an empty complete encoding", ErrInvalidValue)
	}
	return data, nil
}

// EncodeChoiceIndex encodes a CHOICE index for root alternatives.
func EncodeChoiceIndex(bb *BitBuffer, index int64, numAlternatives int, extensible bool) error {
	// X.680 (02/2021) §29.1 requires a root NamedType; X.691
	// (02/2021) §23.4 omits the index only for a singleton root.
	if numAlternatives <= 0 {
		return fmt.Errorf("%w: nonpositive CHOICE root count %d", ErrInvalidValue, numAlternatives)
	}
	if index < 0 || !extensible && index >= int64(numAlternatives) {
		return fmt.Errorf("%w: CHOICE index %d outside %d root alternatives", ErrInvalidValue, index, numAlternatives)
	}
	if extensible {
		isExtension := index >= int64(numAlternatives)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			if index < int64(numAlternatives) {
				return fmt.Errorf("%w: CHOICE extension index below root", ErrInvalidValue)
			}
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
	if numAlternatives <= 0 {
		return 0, false, fmt.Errorf("%w: nonpositive CHOICE root count %d", ErrInvalidValue, numAlternatives)
	}
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
			index, err := addExtensionIndex(numAlternatives, idx)
			return index, true, err
		}
	}
	if numAlternatives <= 1 {
		return 0, false, nil
	}
	idx, err := DecodeConstrainedWholeNumber(bb, 0, int64(numAlternatives-1))
	return idx, false, err
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

// --- internal helpers ---

func encodeLengthDelimitedBits(bb *BitBuffer, data []byte, bitLength int, aligned bool) error {
	required, err := octetsForBitLength(bitLength)
	if err != nil {
		return fmt.Errorf("BIT STRING length: %w", err)
	}
	if required > len(data) {
		return fmt.Errorf("%w: BIT STRING length %d bits requires %d octets, source has %d octets", ErrInvalidValue, bitLength, required, len(data))
	}
	return EncodeLengthFragments(bb, int64(bitLength), aligned, func(offset, length int64) error {
		if aligned {
			if err := bb.AlignToOctetWrite(); err != nil {
				return err
			}
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
	total, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(_ int64, length int64) error {
		if aligned {
			if err := bb.AlignToOctetRead(); err != nil {
				return err
			}
		}
		remaining := bb.BitsRemaining()
		if remaining < 0 {
			return fmt.Errorf("%w: negative remaining PER bits %d", ErrInvalidValue, remaining)
		}
		if length < 0 || length > int64(remaining) || length > int64(math.MaxInt) {
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
		return 0, fmt.Errorf("%w: zero-length semi-constrained INTEGER", ErrInvalidValue)
	}
	if length < 0 || length > 8 {
		return 0, fmt.Errorf("%w: non-negative integer uses %d octets, maximum is 8", ErrInvalidValue, length)
	}
	var data []byte
	data, err = bb.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}
	// ITU-T X.691 (02/2021) §§11.3.6, 11.7.4 require minimum octets.
	if err := validateMinimalUnsigned(data); err != nil {
		return 0, err
	}
	var val uint64
	for _, b := range data {
		if val > math.MaxUint64>>8 {
			return 0, fmt.Errorf("%w: non-negative integer exceeds uint64", ErrInvalidValue)
		}
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
