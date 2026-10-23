// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/integer_big.go; SHA-256 a06c610856f8d5a16ef86fbb7626d44c9a6fe221dd78749736b3287c8feabb95.
package uper

import (
	"fmt"
	"math"
	"math/big"
)

// EncodeIntegerBig encodes an arbitrary-width INTEGER using unaligned PER.
// See ITU-T X.691 (02/2021), clauses 11.4, 11.7-11.9, and 13.
func EncodeIntegerBig(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible bool) error {
	return encodeIntegerBig(bb, value, lower, upper, extensible, false)
}

// DecodeIntegerBig decodes an arbitrary-width INTEGER using unaligned PER.
func DecodeIntegerBig(bb *BitBuffer, lower, upper *int64, extensible bool) (*big.Int, error) {
	return decodeIntegerBig(bb, lower, upper, extensible, false)
}

// EncodeIntegerBigUint64RootAligned is the APER form of EncodeIntegerBigUint64Root.

// DecodeIntegerBigUint64RootAligned is the APER form of DecodeIntegerBigUint64Root.

func encodeIntegerBig(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible, aligned bool) error {
	return encodeIntegerBigBounds(bb, value, bigIntFromInt64Pointer(lower), bigIntFromInt64Pointer(upper), extensible, false)
}

func decodeIntegerBig(bb *BitBuffer, lower, upper *int64, extensible, aligned bool) (*big.Int, error) {
	return decodeIntegerBigBounds(bb, bigIntFromInt64Pointer(lower), bigIntFromInt64Pointer(upper), extensible, false)
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
			return encodeBigTwosComplement(bb, value, false)
		}
	}
	if lower != nil && upper != nil {
		return encodeConstrainedBig(bb, value, lower, upper, false)
	}
	if lower != nil {
		if value.Cmp(lower) < 0 {
			return fmt.Errorf("%w: %s below lower bound %s", ErrConstraintViolation, value, lower)
		}
		offset := new(big.Int).Sub(new(big.Int).Set(value), lower)
		return encodeLengthDelimitedOctets(bb, minimalBigUnsignedBytes(offset), false)
	}
	if upper != nil && value.Cmp(upper) > 0 {
		return fmt.Errorf("%w: %s above upper bound %s", ErrConstraintViolation, value, upper)
	}
	return encodeBigTwosComplement(bb, value, false)
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
			value, err := decodeBigTwosComplement(bb, false)
			if err == nil {
				err = rejectRootValueInExtension(value, integerBigInRootBounds(value, lower, upper))
			}
			return value, err
		}
	}
	if lower != nil && upper != nil {
		return decodeConstrainedBig(bb, lower, upper, false)
	}
	if lower != nil {
		data, err := decodeLengthDelimitedOctets(bb, false)
		if err != nil {
			return nil, err
		}
		if err := validateMinimalUnsigned(data); err != nil {
			return nil, err
		}
		value := new(big.Int).SetBytes(data)
		return value.Add(value, lower), nil
	}
	value, err := decodeBigTwosComplement(bb, false)
	if err != nil {
		return nil, err
	}
	if upper != nil && value.Cmp(upper) > 0 {
		return nil, fmt.Errorf("%w: decoded INTEGER %s above upper bound %s", ErrConstraintViolation, value, upper)
	}
	return value, nil
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
	{
		return writeBigBits(bb, offset, rangeValue.BitLen())
	}

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
	{
		decoded, err := readBigBits(bb, rangeValue.BitLen())
		if err != nil {
			return nil, err
		}
		offset = decoded
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
	return encodeLengthDelimitedOctets(bb, data, false)
}

func decodeBigTwosComplement(bb *BitBuffer, aligned bool) (*big.Int, error) {
	data, err := decodeLengthDelimitedOctets(bb, false)
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
