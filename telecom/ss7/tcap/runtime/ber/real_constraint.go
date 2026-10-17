// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/real_constraint.go; SHA-256 e72c0f08d0c20792e9b04cb8bb58e6ec072a5f32a487d995104c34d041ac27fc.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"math/big"
)

func realRank(value runtime.Real) int {
	switch value.Kind {
	case runtime.RealMinusInfinity:
		return 0
	case runtime.RealMinusZero:
		return 2
	case runtime.RealPlusInfinity:
		return 5
	case runtime.RealNotANumber:
		return 6
	default:
		if value.Mantissa == nil {
			return 3
		}
		if value.Mantissa.Sign() < 0 {
			return 1
		}
		return 4
	}
}

func compareReal(left, right runtime.Real) (int, error) {
	leftRank, rightRank := realRank(left), realRank(right)
	if leftRank < rightRank {
		return -1, nil
	}
	if leftRank > rightRank {
		return 1, nil
	}
	if leftRank != 1 && leftRank != 4 {
		return 0, nil
	}
	leftLow, leftHigh := realMagnitudeBounds(left)
	rightLow, rightHigh := realMagnitudeBounds(right)
	if leftLow.Cmp(rightHigh) >= 0 {
		return signedMagnitudeOrder(leftRank, 1), nil
	}
	if leftHigh.Cmp(rightLow) <= 0 {
		return signedMagnitudeOrder(leftRank, -1), nil
	}
	leftRat, err := boundedRealRat(left)
	if err != nil {
		return 0, err
	}
	rightRat, err := boundedRealRat(right)
	if err != nil {
		return 0, err
	}
	return leftRat.Cmp(rightRat), nil
}

func signedMagnitudeOrder(rank, magnitudeOrder int) int {
	if rank == 1 {
		return -magnitudeOrder
	}
	return magnitudeOrder
}

func realMagnitudeBounds(value runtime.Real) (*big.Int, *big.Int) {
	bits := int64(value.Mantissa.BitLen())
	low := big.NewInt(bits - 1)
	high := big.NewInt(bits)
	if value.Base == 2 {
		return low.Add(low, value.Exponent), high.Add(high, value.Exponent)
	}
	three := new(big.Int).Mul(value.Exponent, big.NewInt(3))
	four := new(big.Int).Mul(value.Exponent, big.NewInt(4))
	if value.Exponent.Sign() >= 0 {
		return low.Add(low, three), high.Add(high, four)
	}
	return low.Add(low, four), high.Add(high, three)
}

func boundedRealRat(value runtime.Real) (*big.Rat, error) {
	const maxExponent = int64(1_000_000)
	if !value.Exponent.IsInt64() {
		return nil, fmt.Errorf("%w: REAL constraint comparison exceeds exact work limit", ErrResourceLimit)
	}
	exponent := value.Exponent.Int64()
	if exponent < -maxExponent || exponent > maxExponent {
		return nil, fmt.Errorf("%w: REAL constraint comparison exceeds exact work limit", ErrResourceLimit)
	}
	numerator := new(big.Int).Set(value.Mantissa)
	denominator := big.NewInt(1)
	if exponent > 0 {
		numerator.Mul(numerator, new(big.Int).Exp(big.NewInt(int64(value.Base)), big.NewInt(exponent), nil))
	} else if exponent < 0 {
		denominator.Exp(big.NewInt(int64(value.Base)), big.NewInt(-exponent), nil)
	}
	return new(big.Rat).SetFrac(numerator, denominator), nil
}
