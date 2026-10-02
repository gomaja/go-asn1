package ber

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/runtime"
)

// RealBound is an exact ASN.1 REAL endpoint represented as a base, mantissa,
// and exponent. ITU-T X.680 (02/2021) §51.4.2 defines REAL range ordering.
type RealBound struct {
	Unbounded bool
	Kind      runtime.RealKind
	Base      int
	Mantissa  string
	Exponent  string
}

// RealRange is a closed REAL value range.
type RealRange struct {
	Lower RealBound
	Upper RealBound
}

// RealConstraintValue formats a REAL without converting it to floating point.
func RealConstraintValue(value runtime.Real) string {
	switch value.Kind {
	case runtime.RealPlusInfinity:
		return "PLUS-INFINITY"
	case runtime.RealMinusInfinity:
		return "MINUS-INFINITY"
	case runtime.RealNotANumber:
		return "NOT-A-NUMBER"
	case runtime.RealMinusZero:
		return "MINUS-ZERO"
	default:
		if value.Mantissa == nil {
			return "0"
		}
		return fmt.Sprintf("%s*%d^%s", value.Mantissa, value.Base, value.Exponent)
	}
}

// RealAllowed checks exact membership in a union of REAL ranges.
func RealAllowed(value runtime.Real, ranges []RealRange) (bool, error) {
	if err := value.Validate(); err != nil {
		return false, err
	}
	for _, item := range ranges {
		lower, err := parseRealBound(item.Lower)
		if err != nil {
			return false, err
		}
		upper, err := parseRealBound(item.Upper)
		if err != nil {
			return false, err
		}
		if !item.Lower.Unbounded && !item.Upper.Unbounded {
			order, err := compareReal(lower, upper)
			if err != nil {
				return false, err
			}
			if order > 0 {
				return false, fmt.Errorf("%w: inverted REAL constraint range", ErrInvalidValue)
			}
		}
		if !item.Lower.Unbounded {
			order, err := compareReal(value, lower)
			if err != nil {
				return false, err
			}
			if order < 0 {
				continue
			}
		}
		if !item.Upper.Unbounded {
			order, err := compareReal(value, upper)
			if err != nil {
				return false, err
			}
			if order > 0 {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

func parseRealBound(bound RealBound) (runtime.Real, error) {
	if bound.Unbounded {
		return runtime.Real{}, nil
	}
	if bound.Kind != runtime.RealFinite {
		return runtime.NewSpecialReal(bound.Kind)
	}
	if bound.Mantissa == "0" {
		return runtime.Real{}, nil
	}
	m, ok := new(big.Int).SetString(bound.Mantissa, 10)
	if !ok {
		return runtime.Real{}, fmt.Errorf("%w: invalid REAL constraint mantissa", ErrInvalidValue)
	}
	e, ok := new(big.Int).SetString(bound.Exponent, 10)
	if !ok {
		return runtime.Real{}, fmt.Errorf("%w: invalid REAL constraint exponent", ErrInvalidValue)
	}
	return runtime.NewReal(bound.Base, m, e)
}

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
		return nil, fmt.Errorf("%w: REAL constraint comparison exceeds exact work limit", ErrInvalidValue)
	}
	exponent := value.Exponent.Int64()
	if exponent < -maxExponent || exponent > maxExponent {
		return nil, fmt.Errorf("%w: REAL constraint comparison exceeds exact work limit", ErrInvalidValue)
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
