// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/integer_octets.go; SHA-256 383eb383fbe8c091747772416458385ddc447b26a95c17f43f2c543152defddc.
package uper

import (
	"fmt"
	"math"
	"math/big"
)

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
