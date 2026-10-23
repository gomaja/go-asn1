// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_big.go; SHA-256 1196dad9ad645fd106cbf598aa4ffe4a066c0c73c665acfec74c6711c09df033.
package aper

import (
	"fmt"
	"math"
	"math/big"
)

const bigFragmentThreshold = 64 * 1024

// EncodeIntegerBigBoundsAligned is the APER form of EncodeIntegerBigBounds.
func EncodeIntegerBigBoundsAligned(bb *BitBuffer, value, lower, upper *big.Int, extensible bool) error {
	return encodeIntegerBigBounds(bb, value, lower, upper, extensible, true)
}

// DecodeIntegerBigBoundsAligned is the APER form of DecodeIntegerBigBounds.
func DecodeIntegerBigBoundsAligned(bb *BitBuffer, lower, upper *big.Int, extensible bool) (*big.Int, error) {
	return decodeIntegerBigBounds(bb, lower, upper, extensible, true)
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
			value, err := decodeBigTwosComplement(bb, aligned)
			if err == nil {
				err = rejectRootValueInExtension(value, integerBigInRootBounds(value, lower, upper))
			}
			return value, err
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

	switch rangeValue.Cmp(big.NewInt(255)) {
	case -1:
		return writeBigBits(bb, offset, rangeValue.BitLen())
	case 0:
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
		}
		return bb.WriteBits(offset.Uint64(), 8)
	}
	if rangeValue.Cmp(big.NewInt(65536)) < 0 {
		if err := bb.AlignToOctetWrite(); err != nil {
			return err
		}
		return bb.WriteBits(offset.Uint64(), 16)
	}
	maximumLength, err := constrainedBigMaximumLength(rangeValue.BitLen())
	if err != nil {
		return err
	}
	data := minimalBigUnsignedBytes(offset)
	// X.691 (02/2021), 13.2.6 delegates to 11.9.3 when the maximum
	// content length is at least 64K, including fragmentation when needed.
	if maximumLength >= bigFragmentThreshold {
		return encodeLengthDelimitedOctets(bb, data, true)
	}
	if err := EncodeConstrainedWholeNumber(bb, int64(len(data)), 1, int64(maximumLength)); err != nil {
		return err
	}
	if err := bb.AlignToOctetWrite(); err != nil {
		return err
	}
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
	if rangeValue.Cmp(big.NewInt(255)) < 0 {
		decoded, err := readBigBits(bb, rangeValue.BitLen())
		if err != nil {
			return nil, err
		}
		offset = decoded
	} else if rangeValue.Cmp(big.NewInt(255)) == 0 {
		if err := bb.AlignToOctetRead(); err != nil {
			return nil, err
		}
		decoded, err := bb.ReadBits(8)
		if err != nil {
			return nil, err
		}
		offset = new(big.Int).SetUint64(decoded)
	} else if rangeValue.Cmp(big.NewInt(65536)) < 0 {
		if err := bb.AlignToOctetRead(); err != nil {
			return nil, err
		}
		decoded, err := bb.ReadBits(16)
		if err != nil {
			return nil, err
		}
		offset = new(big.Int).SetUint64(decoded)
	} else {
		maximumLength, err := constrainedBigMaximumLength(rangeValue.BitLen())
		if err != nil {
			return nil, err
		}
		if maximumLength >= bigFragmentThreshold {
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
				return nil, constrainedOffsetError(lower, offset, upper)
			}
			return new(big.Int).Add(new(big.Int).Set(lower), offset), nil
		}
		length, err := DecodeConstrainedWholeNumber(bb, 1, int64(maximumLength))
		if err != nil {
			return nil, err
		}
		if length < 0 || length > int64(math.MaxInt) {
			return nil, fmt.Errorf("%w: constrained INTEGER length exceeds host int", ErrInvalidValue)
		}
		if err := bb.AlignToOctetRead(); err != nil {
			return nil, err
		}
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
		return nil, constrainedOffsetError(lower, offset, upper)
	}
	return new(big.Int).Add(new(big.Int).Set(lower), offset), nil
}

func writeBigBits(bb *BitBuffer, value *big.Int, bitCount int) error {
	if bitCount < 0 {
		return fmt.Errorf("%w: negative INTEGER bit count %d", ErrInvalidValue, bitCount)
	}
	for index := bitCount; index > 0; {
		index--
		bit := value.Bit(index)
		if bit > 1 {
			return fmt.Errorf("%w: invalid INTEGER bit %d", ErrInvalidValue, bit)
		}
		if err := bb.WriteBit(uint8(bit)); err != nil {
			return err
		}
	}
	return nil
}

func readBigBits(bb *BitBuffer, bitCount int) (*big.Int, error) {
	if bitCount < 0 {
		return nil, fmt.Errorf("%w: negative INTEGER bit count %d", ErrInvalidValue, bitCount)
	}
	value := new(big.Int)
	for index := 0; index < bitCount; {
		bit, err := bb.ReadBit()
		if err != nil {
			return nil, err
		}
		value.Lsh(value, 1)
		if bit != 0 {
			value.SetBit(value, 0, 1)
		}
		index++
	}
	return value, nil
}

func encodeBigTwosComplement(bb *BitBuffer, value *big.Int, aligned bool) error {
	data, err := minimalBigTwosComplement(value)
	if err != nil {
		return err
	}
	return encodeLengthDelimitedOctets(bb, data, aligned)
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
	if len(data) > math.MaxInt/8 {
		return nil, fmt.Errorf("%w: INTEGER bit length exceeds host int", ErrInvalidValue)
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

func minimalBigTwosComplement(value *big.Int) ([]byte, error) {
	if value.Sign() >= 0 {
		data := minimalBigUnsignedBytes(value)
		if data[0]&0x80 != 0 {
			if len(data) == math.MaxInt {
				return nil, fmt.Errorf("%w: INTEGER width exceeds host int", ErrInvalidValue)
			}
			return append([]byte{0}, data...), nil
		}
		return data, nil
	}

	complement := new(big.Int).Sub(new(big.Int).Neg(new(big.Int).Set(value)), big.NewInt(1))
	width, err := negativeTwosComplementWidth(complement.BitLen())
	if err != nil {
		return nil, err
	}
	// X.691 (02/2021) §§11.4, 11.7-11.9: signed INTEGER contents use
	// minimal two's-complement octets. The shift fits the host's int.
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(width*8))
	encoded := new(big.Int).Add(modulus, value)
	return encoded.FillBytes(make([]byte, width)), nil
}

func negativeTwosComplementWidth(bitLen int) (int, error) {
	if bitLen < 0 || bitLen/8 >= math.MaxInt/8 {
		return 0, fmt.Errorf("%w: INTEGER bit width exceeds host int", ErrInvalidValue)
	}
	return bitLen/8 + 1, nil
}

// X.691 (02/2021) §§11.4, 11.7-11.9, 13 encode a constrained INTEGER
// using a whole-octet maximum; divide before rounding to preserve MaxInt bits.
func constrainedBigMaximumLength(bitLen int) (int, error) {
	return octetsForBitLength(bitLen)
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

// EncodeIntegerValueSetBigAligned writes an INTEGER with disjoint root ranges
// in aligned PER (ITU-T X.691 (02/2021) 13.1-13.2).
func EncodeIntegerValueSetBigAligned(bb *BitBuffer, value *big.Int, ranges []IntegerRange, extensible bool) error {
	return encodeIntegerValueSetBig(bb, value, ranges, extensible)
}

// DecodeIntegerValueSetBigAligned reads an INTEGER with disjoint root ranges
// in aligned PER (ITU-T X.691 (02/2021) 13.1-13.2).
func DecodeIntegerValueSetBigAligned(bb *BitBuffer, ranges []IntegerRange, extensible bool) (*big.Int, error) {
	return decodeIntegerValueSetBig(bb, ranges, extensible)
}

func encodeIntegerValueSetBig(bb *BitBuffer, value *big.Int, ranges []IntegerRange, extensible bool) error {
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
			return encodeBigTwosComplement(bb, value, true)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %s is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return EncodeConstrainedWholeNumberAligned(bb, value.Int64(), minimum, maximum)
}

func decodeIntegerValueSetBig(bb *BitBuffer, ranges []IntegerRange, extensible bool) (*big.Int, error) {
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
			value, err := decodeBigTwosComplement(bb, true)
			if err == nil {
				err = rejectRootValueInExtension(value, value.IsInt64() && integerSetContains(value.Int64(), ranges))
			}
			return value, err
		}
	}
	value, err := DecodeConstrainedWholeNumberAligned(bb, minimum, maximum)
	if err != nil {
		return nil, err
	}
	if !integerSetContains(value, ranges) {
		return nil, fmt.Errorf("%w: decoded root value %d is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return big.NewInt(value), nil
}
