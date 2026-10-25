// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/integer_oracle_test.go; SHA-256 cad034605608af583a57433551ffe756adf2349a4fde8661bb676e37e4ccc947.
package uper

import (
	"fmt"
	"math"
	"math/big"
)

func encodeBigTwosComplement(bb *BitBuffer, value *big.Int, aligned bool) error {
	data, err := minimalBigTwosComplement(value)
	if err != nil {
		return err
	}
	return encodeLengthDelimitedOctets(bb, data, false)
}

func encodeTestIntegerBig(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible bool) error {
	if extensible {
		inRoot := value.IsInt64() && (lower == nil || value.Int64() >= *lower) && (upper == nil || value.Int64() <= *upper)
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if inRoot {
			return EncodeInteger(bb, value.Int64(), lower, upper, false)
		}
	}
	return encodeBigTwosComplement(bb, value, false)
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

func minimalBigUnsignedBytes(value *big.Int) []byte {
	data := value.Bytes()
	if len(data) == 0 {
		return []byte{0}
	}
	return data
}
