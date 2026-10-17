// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/real.go; SHA-256 13b3474f95b00afe4677e8bdf5e1611af93dcd70c37141eca46fbf70cb58d299.
package runtime

import (
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrInvalidReal   = errors.New("asn1: invalid REAL value")
	ErrRealOverflow  = errors.New("asn1: REAL overflows float64")
	ErrRealUnderflow = errors.New("asn1: REAL underflows float64")
)

// RealKind identifies a finite or special ASN.1 REAL value.
type RealKind uint8

const (
	RealFinite RealKind = iota
	RealPlusInfinity
	RealMinusInfinity
	RealNotANumber
	RealMinusZero
)

// Real is the exact ASN.1 REAL abstract value {mantissa, base, exponent}.
// Finite non-zero values use base 2 or 10 and arbitrary-width integers. The
// zero value is ASN.1 plus zero. See ITU-T X.690 (02/2021), clause 8.5.
type Real struct {
	Kind     RealKind `json:"kind"`
	Base     int      `json:"base,omitempty"`
	Mantissa *big.Int `json:"mantissa,omitempty"`
	Exponent *big.Int `json:"exponent,omitempty"`
	berForm  *realBERForm
}

type realBERForm struct {
	contents []byte
	kind     RealKind
	base     int
	mantissa *big.Int
	exponent *big.Int
}

// NewReal constructs and normalizes a finite ASN.1 REAL value.
func NewReal(base int, mantissa, exponent *big.Int) (Real, error) {
	if mantissa == nil || exponent == nil {
		return Real{}, fmt.Errorf("%w: finite value requires mantissa and exponent", ErrInvalidReal)
	}
	if base != 2 && base != 10 {
		return Real{}, fmt.Errorf("%w: finite value base %d is not 2 or 10", ErrInvalidReal, base)
	}
	if mantissa.Sign() == 0 {
		return Real{}, nil
	}

	m := new(big.Int).Set(mantissa)
	e := new(big.Int).Set(exponent)
	if base == 2 {
		absolute := new(big.Int).Abs(new(big.Int).Set(m))
		shift := absolute.TrailingZeroBits()
		if shift != 0 {
			m.Rsh(m, shift)
			e.Add(e, new(big.Int).SetUint64(uint64(shift)))
		}
	} else {
		// A decoded decimal mantissa may be millions of digits long. Avoid
		// converting it to text and parsing it again to strip powers of ten.
		// Squared powers remove any trailing zeros in logarithmically many
		// exact big.Int divisions (X.690 (02/2021) §8.5.8).
		absolute := new(big.Int).Abs(m)
		ten := big.NewInt(10)
		if new(big.Int).Mod(absolute, ten).Sign() == 0 {
			quotient := new(big.Int)
			remainder := new(big.Int)
			smallZeros := 0
			for smallZeros < 16 {
				quotient.QuoRem(absolute, ten, remainder)
				if remainder.Sign() != 0 {
					break
				}
				absolute.Set(quotient)
				smallZeros++
			}
			zeros := big.NewInt(int64(smallZeros))
			if smallZeros == 16 && new(big.Int).Mod(absolute, ten).Sign() == 0 {
				var powers []*big.Int
				for power := ten; power.Cmp(absolute) <= 0; power = new(big.Int).Mul(power, power) {
					powers = append(powers, power)
				}
				for i := len(powers); i > 0; {
					i--
					quotient.QuoRem(absolute, powers[i], remainder)
					if remainder.Sign() != 0 {
						continue
					}
					absolute.Set(quotient)
					zeros.Add(zeros, new(big.Int).Lsh(big.NewInt(1), uint(i)))
				}
			}
			m.Set(absolute)
			if mantissa.Sign() < 0 {
				m.Neg(m)
			}
			e.Add(e, zeros)
		}
	}
	return Real{Kind: RealFinite, Base: base, Mantissa: m, Exponent: e}, nil
}

// NewSpecialReal constructs an ASN.1 REAL special value.
func NewSpecialReal(kind RealKind) (Real, error) {
	switch kind {
	case RealPlusInfinity, RealMinusInfinity, RealNotANumber, RealMinusZero:
		return Real{Kind: kind}, nil
	default:
		return Real{}, fmt.Errorf("%w: kind %d is not a special value", ErrInvalidReal, kind)
	}
}

// Validate checks that the value has one unambiguous ASN.1 REAL state.
func (value Real) Validate() error {
	switch value.Kind {
	case RealFinite:
		if value.Mantissa == nil {
			if value.Base == 0 && value.Exponent == nil {
				return nil
			}
			return fmt.Errorf("%w: plus zero must not carry finite components", ErrInvalidReal)
		}
		if value.Mantissa.Sign() == 0 {
			return fmt.Errorf("%w: plus zero must use the zero Real value", ErrInvalidReal)
		}
		if value.Base != 2 && value.Base != 10 {
			return fmt.Errorf("%w: finite value base %d is not 2 or 10", ErrInvalidReal, value.Base)
		}
		if value.Exponent == nil {
			return fmt.Errorf("%w: finite value has no exponent", ErrInvalidReal)
		}
		return nil
	case RealPlusInfinity, RealMinusInfinity, RealNotANumber, RealMinusZero:
		if value.Base != 0 || value.Mantissa != nil || value.Exponent != nil {
			return fmt.Errorf("%w: special value carries finite components", ErrInvalidReal)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown kind %d", ErrInvalidReal, value.Kind)
	}
}

// Canonical returns a normalized copy of value.
func (value Real) Canonical() (Real, error) {
	if err := value.Validate(); err != nil {
		return Real{}, err
	}
	if value.Kind != RealFinite || value.Mantissa == nil {
		return Real{Kind: value.Kind}, nil
	}
	return NewReal(value.Base, value.Mantissa, value.Exponent)
}
