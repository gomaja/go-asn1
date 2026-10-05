package ber

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/runtime"
)

// RealEqualsDERDefault compares exact ASN.1 REAL values across binary and
// decimal representations for the DEFAULT omission rule in ITU-T X.690
// (02/2021) §11.5. It never converts through float64.
func RealEqualsDERDefault(value runtime.Real, defaultDER string) (bool, error) {
	other, consumed, err := DecodeReal([]byte(defaultDER))
	if err != nil {
		return false, fmt.Errorf("decoding REAL DEFAULT: %w", err)
	}
	if consumed != len(defaultDER) {
		return false, fmt.Errorf("%w: REAL DEFAULT has trailing data", ErrExtraData)
	}
	left, err := value.Canonical()
	if err != nil {
		return false, err
	}
	right, err := other.Canonical()
	if err != nil {
		return false, err
	}
	if left.Kind != right.Kind {
		return false, nil
	}
	if left.Kind != runtime.RealFinite {
		return true, nil
	}
	if left.Mantissa == nil || right.Mantissa == nil {
		return left.Mantissa == nil && right.Mantissa == nil, nil
	}
	leftMantissa, leftTwo, leftFive := realFactors(left)
	rightMantissa, rightTwo, rightFive := realFactors(right)
	return leftMantissa.Cmp(rightMantissa) == 0 &&
		leftTwo.Cmp(rightTwo) == 0 && leftFive.Cmp(rightFive) == 0, nil
}

func realFactors(value runtime.Real) (*big.Int, *big.Int, *big.Int) {
	mantissa := new(big.Int).Set(value.Mantissa)
	two := new(big.Int).Set(value.Exponent)
	five := new(big.Int)
	if value.Base == 10 {
		five.Set(value.Exponent)
	}
	abs := new(big.Int).Abs(new(big.Int).Set(mantissa))
	shift := abs.TrailingZeroBits()
	if shift != 0 {
		mantissa.Rsh(mantissa, shift)
		two.Add(two, new(big.Int).SetUint64(uint64(shift)))
	}
	abs.Abs(mantissa)
	// Factor the exact REAL value for X.690 (02/2021) §11.5 without one
	// division per factor: decoded mantissas can contain arbitrarily many 5s.
	// Squared powers let each successful division remove 2^k factors.
	if abs.Sign() != 0 && new(big.Int).Mod(abs, big.NewInt(5)).Sign() == 0 {
		var powers []*big.Int
		for power := big.NewInt(5); power.Cmp(abs) <= 0; power = new(big.Int).Mul(power, power) {
			powers = append(powers, power)
		}
		quotient := new(big.Int)
		remainder := new(big.Int)
		for i := len(powers); i > 0; {
			i--
			quotient.QuoRem(abs, powers[i], remainder)
			if remainder.Sign() != 0 {
				continue
			}
			abs.Set(quotient)
			five.Add(five, new(big.Int).Lsh(big.NewInt(1), uint(i)))
		}
		mantissa.Set(abs)
		if value.Mantissa.Sign() < 0 {
			mantissa.Neg(mantissa)
		}
	}
	return mantissa, two, five
}
