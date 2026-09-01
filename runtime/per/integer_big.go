package per

import (
	"fmt"
	"math/big"
)

const perFragmentUnit = 16 * 1024

// EncodeIntegerBig encodes an arbitrary-width INTEGER using unaligned PER.
// See ITU-T X.691 (02/2021), clauses 11.4, 11.7-11.9, and 13.
func EncodeIntegerBig(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible bool) error {
	return encodeIntegerBig(bb, value, lower, upper, extensible, false)
}

// DecodeIntegerBig decodes an arbitrary-width INTEGER using unaligned PER.
func DecodeIntegerBig(bb *BitBuffer, lower, upper *int64, extensible bool) (*big.Int, error) {
	return decodeIntegerBig(bb, lower, upper, extensible, false)
}

// EncodeIntegerBigAligned encodes an arbitrary-width INTEGER using aligned PER.
// See ITU-T X.691 (02/2021), clauses 11.4, 11.7-11.9, and 13.
func EncodeIntegerBigAligned(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible bool) error {
	return encodeIntegerBig(bb, value, lower, upper, extensible, true)
}

// DecodeIntegerBigAligned decodes an arbitrary-width INTEGER using aligned PER.
func DecodeIntegerBigAligned(bb *BitBuffer, lower, upper *int64, extensible bool) (*big.Int, error) {
	return decodeIntegerBig(bb, lower, upper, extensible, true)
}

// EncodeIntegerBigBounds encodes an arbitrary-width INTEGER with arbitrary-
// width root bounds using unaligned PER.
func EncodeIntegerBigBounds(bb *BitBuffer, value, lower, upper *big.Int, extensible bool) error {
	return encodeIntegerBigBounds(bb, value, lower, upper, extensible, false)
}

// DecodeIntegerBigBounds decodes an arbitrary-width INTEGER with arbitrary-
// width root bounds using unaligned PER.
func DecodeIntegerBigBounds(bb *BitBuffer, lower, upper *big.Int, extensible bool) (*big.Int, error) {
	return decodeIntegerBigBounds(bb, lower, upper, extensible, false)
}

// EncodeIntegerBigBoundsAligned is the APER form of EncodeIntegerBigBounds.
func EncodeIntegerBigBoundsAligned(bb *BitBuffer, value, lower, upper *big.Int, extensible bool) error {
	return encodeIntegerBigBounds(bb, value, lower, upper, extensible, true)
}

// DecodeIntegerBigBoundsAligned is the APER form of DecodeIntegerBigBounds.
func DecodeIntegerBigBoundsAligned(bb *BitBuffer, lower, upper *big.Int, extensible bool) (*big.Int, error) {
	return decodeIntegerBigBounds(bb, lower, upper, extensible, true)
}

// EncodeIntegerValueSetBig encodes an arbitrary-width INTEGER constrained by
// a finite root value set using unaligned PER.
func EncodeIntegerValueSetBig(bb *BitBuffer, value *big.Int, ranges []IntegerRange, extensible bool) error {
	return encodeIntegerValueSetBig(bb, value, ranges, extensible, false)
}

// DecodeIntegerValueSetBig decodes an arbitrary-width INTEGER constrained by
// a finite root value set using unaligned PER.
func DecodeIntegerValueSetBig(bb *BitBuffer, ranges []IntegerRange, extensible bool) (*big.Int, error) {
	return decodeIntegerValueSetBig(bb, ranges, extensible, false)
}

// EncodeIntegerValueSetBigAligned is the APER form of EncodeIntegerValueSetBig.
func EncodeIntegerValueSetBigAligned(bb *BitBuffer, value *big.Int, ranges []IntegerRange, extensible bool) error {
	return encodeIntegerValueSetBig(bb, value, ranges, extensible, true)
}

// DecodeIntegerValueSetBigAligned is the APER form of DecodeIntegerValueSetBig.
func DecodeIntegerValueSetBigAligned(bb *BitBuffer, ranges []IntegerRange, extensible bool) (*big.Int, error) {
	return decodeIntegerValueSetBig(bb, ranges, extensible, true)
}

// EncodeIntegerBigUint64Root encodes an arbitrary-width INTEGER whose finite
// extension root has non-negative uint64 bounds using unaligned PER.
func EncodeIntegerBigUint64Root(bb *BitBuffer, value *big.Int, lower, upper uint64, extensible bool) error {
	return encodeIntegerBigUint64Root(bb, value, lower, upper, extensible, false)
}

// DecodeIntegerBigUint64Root decodes the unaligned PER form produced by
// EncodeIntegerBigUint64Root.
func DecodeIntegerBigUint64Root(bb *BitBuffer, lower, upper uint64, extensible bool) (*big.Int, error) {
	return decodeIntegerBigUint64Root(bb, lower, upper, extensible, false)
}

// EncodeIntegerBigUint64RootAligned is the APER form of EncodeIntegerBigUint64Root.
func EncodeIntegerBigUint64RootAligned(bb *BitBuffer, value *big.Int, lower, upper uint64, extensible bool) error {
	return encodeIntegerBigUint64Root(bb, value, lower, upper, extensible, true)
}

// DecodeIntegerBigUint64RootAligned is the APER form of DecodeIntegerBigUint64Root.
func DecodeIntegerBigUint64RootAligned(bb *BitBuffer, lower, upper uint64, extensible bool) (*big.Int, error) {
	return decodeIntegerBigUint64Root(bb, lower, upper, extensible, true)
}

func encodeIntegerBig(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible, aligned bool) error {
	return encodeIntegerBigBounds(bb, value, bigIntFromInt64Pointer(lower), bigIntFromInt64Pointer(upper), extensible, aligned)
}

func decodeIntegerBig(bb *BitBuffer, lower, upper *int64, extensible, aligned bool) (*big.Int, error) {
	return decodeIntegerBigBounds(bb, bigIntFromInt64Pointer(lower), bigIntFromInt64Pointer(upper), extensible, aligned)
}

func encodeIntegerBigBounds(bb *BitBuffer, value, lower, upper *big.Int, extensible, aligned bool) error {
	if value == nil {
		return fmt.Errorf("%w: INTEGER value is nil", ErrInvalidValue)
	}
	if lower != nil && upper != nil && lower.Cmp(upper) > 0 {
		return fmt.Errorf("%w: invalid INTEGER range [%s..%s]", ErrInvalidValue, lower, upper)
	}
	if extensible {
		inRoot := integerBigInRootBounds(value, lower, upper)
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeBigTwosComplement(bb, value, aligned)
		}
	}
	if lower != nil && upper != nil {
		return encodeConstrainedBig(bb, value, lower, upper, aligned)
	}
	if lower != nil {
		if value.Cmp(lower) < 0 {
			return fmt.Errorf("%w: %s below lower bound %s", ErrConstraintViolation, value, lower)
		}
		offset := new(big.Int).Sub(new(big.Int).Set(value), lower)
		return encodeLengthDelimitedOctets(bb, minimalBigUnsignedBytes(offset), aligned)
	}
	if upper != nil && value.Cmp(upper) > 0 {
		return fmt.Errorf("%w: %s above upper bound %s", ErrConstraintViolation, value, upper)
	}
	return encodeBigTwosComplement(bb, value, aligned)
}

func decodeIntegerBigBounds(bb *BitBuffer, lower, upper *big.Int, extensible, aligned bool) (*big.Int, error) {
	if lower != nil && upper != nil && lower.Cmp(upper) > 0 {
		return nil, fmt.Errorf("%w: invalid INTEGER range [%s..%s]", ErrInvalidValue, lower, upper)
	}
	if extensible {
		outside, err := DecodeBoolean(bb)
		if err != nil {
			return nil, err
		}
		if outside {
			return decodeBigTwosComplement(bb, aligned)
		}
	}
	if lower != nil && upper != nil {
		return decodeConstrainedBig(bb, lower, upper, aligned)
	}
	if lower != nil {
		data, err := decodeLengthDelimitedOctets(bb, aligned)
		if err != nil {
			return nil, err
		}
		if err := validateMinimalUnsigned(data); err != nil {
			return nil, err
		}
		value := new(big.Int).SetBytes(data)
		return value.Add(value, lower), nil
	}
	value, err := decodeBigTwosComplement(bb, aligned)
	if err != nil {
		return nil, err
	}
	if upper != nil && value.Cmp(upper) > 0 {
		return nil, fmt.Errorf("%w: decoded INTEGER %s above upper bound %s", ErrConstraintViolation, value, upper)
	}
	return value, nil
}

func encodeIntegerValueSetBig(bb *BitBuffer, value *big.Int, ranges []IntegerRange, extensible, aligned bool) error {
	if value == nil {
		return fmt.Errorf("%w: INTEGER value is nil", ErrInvalidValue)
	}
	minimum, maximum, _, err := integerSetBounds(0, ranges)
	if err != nil {
		return err
	}
	inRoot := value.IsInt64() && integerSetContains(value.Int64(), ranges)
	if extensible {
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeBigTwosComplement(bb, value, aligned)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %s is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	if aligned {
		return EncodeConstrainedWholeNumberAligned(bb, value.Int64(), minimum, maximum)
	}
	return EncodeConstrainedWholeNumber(bb, value.Int64(), minimum, maximum)
}

func decodeIntegerValueSetBig(bb *BitBuffer, ranges []IntegerRange, extensible, aligned bool) (*big.Int, error) {
	minimum, maximum, _, err := integerSetBounds(0, ranges)
	if err != nil {
		return nil, err
	}
	if extensible {
		outside, decodeErr := DecodeBoolean(bb)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if outside {
			return decodeBigTwosComplement(bb, aligned)
		}
	}
	var value int64
	if aligned {
		value, err = DecodeConstrainedWholeNumberAligned(bb, minimum, maximum)
	} else {
		value, err = DecodeConstrainedWholeNumber(bb, minimum, maximum)
	}
	if err != nil {
		return nil, err
	}
	if !integerSetContains(value, ranges) {
		return nil, fmt.Errorf("%w: decoded root value %d is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return big.NewInt(value), nil
}

func encodeIntegerBigUint64Root(bb *BitBuffer, value *big.Int, lower, upper uint64, extensible, aligned bool) error {
	if value == nil {
		return fmt.Errorf("%w: INTEGER value is nil", ErrInvalidValue)
	}
	if lower > upper {
		return fmt.Errorf("%w: invalid uint64 INTEGER range [%d..%d]", ErrInvalidValue, lower, upper)
	}
	inRoot := value.Sign() >= 0 && value.IsUint64() && value.Uint64() >= lower && value.Uint64() <= upper
	if extensible {
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeBigTwosComplement(bb, value, aligned)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %s is outside uint64 INTEGER root [%d..%d]", ErrConstraintViolation, value, lower, upper)
	}
	if aligned {
		return EncodeIntegerUint64Aligned(bb, value.Uint64(), lower, upper, false)
	}
	return EncodeIntegerUint64(bb, value.Uint64(), lower, upper, false)
}

func decodeIntegerBigUint64Root(bb *BitBuffer, lower, upper uint64, extensible, aligned bool) (*big.Int, error) {
	if lower > upper {
		return nil, fmt.Errorf("%w: invalid uint64 INTEGER range [%d..%d]", ErrInvalidValue, lower, upper)
	}
	if extensible {
		outside, err := DecodeBoolean(bb)
		if err != nil {
			return nil, err
		}
		if outside {
			return decodeBigTwosComplement(bb, aligned)
		}
	}
	var (
		value uint64
		err   error
	)
	if aligned {
		value, err = DecodeIntegerUint64Aligned(bb, lower, upper, false)
	} else {
		value, err = DecodeIntegerUint64(bb, lower, upper, false)
	}
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetUint64(value), nil
}

func bigIntFromInt64Pointer(value *int64) *big.Int {
	if value == nil {
		return nil
	}
	return big.NewInt(*value)
}

func integerBigInRootBounds(value, lower, upper *big.Int) bool {
	if lower != nil && value.Cmp(lower) < 0 {
		return false
	}
	return upper == nil || value.Cmp(upper) <= 0
}

func encodeConstrainedBig(bb *BitBuffer, value, lower, upper *big.Int, aligned bool) error {
	rangeValue := new(big.Int).Sub(new(big.Int).Set(upper), lower)
	if rangeValue.Sign() < 0 {
		return fmt.Errorf("%w: invalid INTEGER range [%s..%s]", ErrInvalidValue, lower, upper)
	}
	if value.Cmp(lower) < 0 || value.Cmp(upper) > 0 {
		return fmt.Errorf("%w: %s not in [%s..%s]", ErrConstraintViolation, value, lower, upper)
	}
	if rangeValue.Sign() == 0 {
		return nil
	}
	offset := new(big.Int).Sub(new(big.Int).Set(value), lower)
	if !aligned {
		return writeBigBits(bb, offset, rangeValue.BitLen())
	}

	switch rangeValue.Cmp(big.NewInt(255)) {
	case -1:
		return writeBigBits(bb, offset, rangeValue.BitLen())
	case 0:
		bb.AlignToOctetWrite()
		return bb.WriteBits(offset.Uint64(), 8)
	}
	if rangeValue.Cmp(big.NewInt(65536)) < 0 {
		bb.AlignToOctetWrite()
		return bb.WriteBits(offset.Uint64(), 16)
	}
	maximumLength := (rangeValue.BitLen() + 7) / 8
	data := minimalBigUnsignedBytes(offset)
	// X.691 (02/2021), 13.2.6 delegates to 11.9.3 when the maximum
	// content length is at least 64K, including fragmentation when needed.
	if maximumLength >= 4*perFragmentUnit {
		return encodeLengthDelimitedOctets(bb, data, true)
	}
	if err := EncodeConstrainedWholeNumber(bb, int64(len(data)), 1, int64(maximumLength)); err != nil {
		return err
	}
	bb.AlignToOctetWrite()
	return bb.WriteBytes(data)
}

func decodeConstrainedBig(bb *BitBuffer, lower, upper *big.Int, aligned bool) (*big.Int, error) {
	rangeValue := new(big.Int).Sub(new(big.Int).Set(upper), lower)
	if rangeValue.Sign() < 0 {
		return nil, fmt.Errorf("%w: invalid INTEGER range [%s..%s]", ErrInvalidValue, lower, upper)
	}
	if rangeValue.Sign() == 0 {
		return new(big.Int).Set(lower), nil
	}

	var offset *big.Int
	if !aligned || rangeValue.Cmp(big.NewInt(255)) < 0 {
		decoded, err := readBigBits(bb, rangeValue.BitLen())
		if err != nil {
			return nil, err
		}
		offset = decoded
	} else if rangeValue.Cmp(big.NewInt(255)) == 0 {
		bb.AlignToOctetRead()
		decoded, err := bb.ReadBits(8)
		if err != nil {
			return nil, err
		}
		offset = new(big.Int).SetUint64(decoded)
	} else if rangeValue.Cmp(big.NewInt(65536)) < 0 {
		bb.AlignToOctetRead()
		decoded, err := bb.ReadBits(16)
		if err != nil {
			return nil, err
		}
		offset = new(big.Int).SetUint64(decoded)
	} else {
		maximumLength := (rangeValue.BitLen() + 7) / 8
		if maximumLength >= 4*perFragmentUnit {
			data, err := decodeLengthDelimitedOctets(bb, true)
			if err != nil {
				return nil, err
			}
			if len(data) > maximumLength {
				return nil, fmt.Errorf("%w: constrained INTEGER length %d exceeds maximum %d", ErrConstraintViolation, len(data), maximumLength)
			}
			if err := validateMinimalUnsigned(data); err != nil {
				return nil, err
			}
			offset = new(big.Int).SetBytes(data)
			if offset.Cmp(rangeValue) > 0 {
				return nil, fmt.Errorf("%w: constrained INTEGER offset %s exceeds range %s", ErrInvalidValue, offset, rangeValue)
			}
			return new(big.Int).Add(new(big.Int).Set(lower), offset), nil
		}
		length, err := DecodeConstrainedWholeNumber(bb, 1, int64(maximumLength))
		if err != nil {
			return nil, err
		}
		bb.AlignToOctetRead()
		data, err := bb.ReadBytes(int(length))
		if err != nil {
			return nil, err
		}
		if err := validateMinimalUnsigned(data); err != nil {
			return nil, err
		}
		offset = new(big.Int).SetBytes(data)
	}
	if offset.Cmp(rangeValue) > 0 {
		return nil, fmt.Errorf("%w: constrained INTEGER offset %s exceeds range %s", ErrInvalidValue, offset, rangeValue)
	}
	return new(big.Int).Add(new(big.Int).Set(lower), offset), nil
}

func writeBigBits(bb *BitBuffer, value *big.Int, bitCount int) error {
	for index := bitCount - 1; index >= 0; index-- {
		if err := bb.WriteBit(uint8(value.Bit(index))); err != nil {
			return err
		}
	}
	return nil
}

func readBigBits(bb *BitBuffer, bitCount int) (*big.Int, error) {
	value := new(big.Int)
	for index := 0; index < bitCount; index++ {
		bit, err := bb.ReadBit()
		if err != nil {
			return nil, err
		}
		value.Lsh(value, 1)
		if bit != 0 {
			value.SetBit(value, 0, 1)
		}
	}
	return value, nil
}

func encodeBigTwosComplement(bb *BitBuffer, value *big.Int, aligned bool) error {
	return encodeLengthDelimitedOctets(bb, minimalBigTwosComplement(value), aligned)
}

func decodeBigTwosComplement(bb *BitBuffer, aligned bool) (*big.Int, error) {
	data, err := decodeLengthDelimitedOctets(bb, aligned)
	if err != nil {
		return nil, err
	}
	if err := validateMinimalTwosComplement(data); err != nil {
		return nil, err
	}
	value := new(big.Int).SetBytes(data)
	if data[0]&0x80 == 0 {
		return value, nil
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(len(data)*8))
	return value.Sub(value, modulus), nil
}

func minimalBigUnsignedBytes(value *big.Int) []byte {
	data := value.Bytes()
	if len(data) == 0 {
		return []byte{0}
	}
	return data
}

func minimalBigTwosComplement(value *big.Int) []byte {
	if value.Sign() >= 0 {
		data := minimalBigUnsignedBytes(value)
		if data[0]&0x80 != 0 {
			return append([]byte{0}, data...)
		}
		return data
	}

	complement := new(big.Int).Sub(new(big.Int).Neg(new(big.Int).Set(value)), big.NewInt(1))
	width := (complement.BitLen() + 1 + 7) / 8
	if width == 0 {
		width = 1
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(width*8))
	encoded := new(big.Int).Add(modulus, value)
	return encoded.FillBytes(make([]byte, width))
}

func validateMinimalUnsigned(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: zero-length semi-constrained INTEGER", ErrInvalidValue)
	}
	if len(data) > 1 && data[0] == 0 {
		return fmt.Errorf("%w: non-minimal non-negative INTEGER", ErrInvalidValue)
	}
	return nil
}

func validateMinimalTwosComplement(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: zero-length unconstrained INTEGER", ErrInvalidValue)
	}
	if len(data) > 1 && (data[0] == 0 && data[1]&0x80 == 0 || data[0] == 0xff && data[1]&0x80 != 0) {
		return fmt.Errorf("%w: non-minimal two's-complement INTEGER", ErrInvalidValue)
	}
	return nil
}

func encodeLengthDelimitedOctets(bb *BitBuffer, data []byte, aligned bool) error {
	remaining := data
	for len(remaining) >= perFragmentUnit {
		multiplier := len(remaining) / perFragmentUnit
		if multiplier > 4 {
			multiplier = 4
		}
		fragmentLength := multiplier * perFragmentUnit
		if aligned {
			bb.AlignToOctetWrite()
		}
		if err := bb.WriteBits(uint64(0xc0|multiplier), 8); err != nil {
			return err
		}
		if err := bb.WriteBytes(remaining[:fragmentLength]); err != nil {
			return err
		}
		remaining = remaining[fragmentLength:]
	}
	if aligned {
		bb.AlignToOctetWrite()
	}
	if err := EncodeUnconstrainedLength(bb, int64(len(remaining))); err != nil {
		return err
	}
	return bb.WriteBytes(remaining)
}

func decodeLengthDelimitedOctets(bb *BitBuffer, aligned bool) ([]byte, error) {
	var result []byte
	previousFragmentMultiplier := 0
	for {
		if aligned {
			bb.AlignToOctetRead()
		}
		first, err := bb.ReadBits(8)
		if err != nil {
			return nil, err
		}
		var length int
		switch {
		case first&0x80 == 0:
			length = int(first)
		case first&0xc0 == 0x80:
			second, readErr := bb.ReadBits(8)
			if readErr != nil {
				return nil, readErr
			}
			length = int(first&0x3f)<<8 | int(second)
			if length < 128 {
				return nil, fmt.Errorf("%w: non-minimal PER length determinant", ErrInvalidValue)
			}
		case first&0xc0 == 0xc0:
			multiplier := int(first & 0x3f)
			if multiplier < 1 || multiplier > 4 {
				return nil, fmt.Errorf("%w: invalid PER fragment multiplier %d", ErrInvalidValue, multiplier)
			}
			// X.691 (02/2021), 11.9.3.8.1 requires the largest applicable
			// multiplier. A following fragment proves that a prior multiplier
			// below four was not maximal.
			if previousFragmentMultiplier != 0 && previousFragmentMultiplier != 4 {
				return nil, fmt.Errorf("%w: non-maximal PER fragment multiplier %d", ErrInvalidValue, previousFragmentMultiplier)
			}
			previousFragmentMultiplier = multiplier
			length = multiplier * perFragmentUnit
		default:
			return nil, fmt.Errorf("%w: invalid PER length determinant", ErrInvalidValue)
		}
		if length > bb.BitsRemaining()/8 {
			return nil, ErrTruncated
		}
		fragment, err := bb.ReadBytes(length)
		if err != nil {
			return nil, err
		}
		result = append(result, fragment...)
		if first&0xc0 != 0xc0 {
			return result, nil
		}
	}
}
