// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/integer_twos.go; SHA-256 6e5c3fd2ef86e2f8e7d0c00ff2ad112c105dfc6877dbbf983c13f349d167ffc5.
package uper

import (
	"fmt"
	"math"
	"math/big"
)

// decodeBigTwosComplement decodes enough precision to reject a source value
// outside the generated int64 API without truncating its diagnostic.
// X.691 (02/2021) §11.8 requires minimal two's-complement contents.
func decodeBigTwosComplement(bb *BitBuffer) (*big.Int, error) {
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

func validateMinimalTwosComplement(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: zero-length unconstrained INTEGER", ErrInvalidValue)
	}
	if len(data) > 1 && (data[0] == 0 && data[1]&0x80 == 0 || data[0] == 0xff && data[1]&0x80 != 0) {
		return fmt.Errorf("%w: non-minimal two's-complement INTEGER", ErrInvalidValue)
	}
	return nil
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
