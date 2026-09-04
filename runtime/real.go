package runtime

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
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
		digits := new(big.Int).Abs(new(big.Int).Set(m)).String()
		trimmed := strings.TrimRight(digits, "0")
		if trimmed != digits {
			m.SetString(trimmed, 10)
			if mantissa.Sign() < 0 {
				m.Neg(m)
			}
			e.Add(e, big.NewInt(int64(len(digits)-len(trimmed))))
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

// NewRealFromFloat64 preserves the exact IEEE 754 value as an ASN.1 REAL.
func NewRealFromFloat64(value float64) Real {
	switch {
	case math.IsInf(value, 1):
		return Real{Kind: RealPlusInfinity}
	case math.IsInf(value, -1):
		return Real{Kind: RealMinusInfinity}
	case math.IsNaN(value):
		return Real{Kind: RealNotANumber}
	case value == 0 && math.Signbit(value):
		return Real{Kind: RealMinusZero}
	case value == 0:
		return Real{}
	}

	bits := math.Float64bits(value)
	rawExponent := int64((bits >> 52) & 0x7ff)
	mantissa := bits & 0x000fffffffffffff
	var exponent int64
	if rawExponent == 0 {
		exponent = 1 - 1023 - 52
	} else {
		exponent = rawExponent - 1023 - 52
		mantissa |= 0x0010000000000000
	}
	m := new(big.Int).SetUint64(mantissa)
	if bits>>63 != 0 {
		m.Neg(m)
	}
	result, err := NewReal(2, m, big.NewInt(exponent))
	if err != nil {
		panic(err)
	}
	return result
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

// Float64 converts value when it is representable without overflowing or
// rounding a non-zero REAL to zero.
func (value Real) Float64() (float64, error) {
	canonical, err := value.Canonical()
	if err != nil {
		return 0, err
	}
	switch canonical.Kind {
	case RealPlusInfinity:
		return math.Inf(1), nil
	case RealMinusInfinity:
		return math.Inf(-1), nil
	case RealNotANumber:
		return math.NaN(), nil
	case RealMinusZero:
		return math.Copysign(0, -1), nil
	}
	if canonical.Mantissa == nil {
		return 0, nil
	}

	var result *big.Float
	precision := uint(canonical.Mantissa.BitLen() + 64)
	if precision < 256 {
		precision = 256
	}
	result = new(big.Float).SetPrec(precision).SetMode(big.ToNearestEven).SetInt(canonical.Mantissa)

	switch canonical.Base {
	case 2:
		magnitude := new(big.Int).Add(canonical.Exponent, big.NewInt(int64(new(big.Int).Abs(new(big.Int).Set(canonical.Mantissa)).BitLen()-1)))
		if magnitude.Cmp(big.NewInt(1023)) > 0 {
			return 0, ErrRealOverflow
		}
		if magnitude.Cmp(big.NewInt(-1075)) < 0 {
			return 0, ErrRealUnderflow
		}
		if !canonical.Exponent.IsInt64() {
			return 0, ErrInvalidReal
		}
		exponent := canonical.Exponent.Int64()
		if int64(int(exponent)) != exponent {
			return 0, ErrInvalidReal
		}
		result.SetMantExp(result, int(exponent))
	case 10:
		digits := len(new(big.Int).Abs(new(big.Int).Set(canonical.Mantissa)).String())
		magnitude := new(big.Int).Add(canonical.Exponent, big.NewInt(int64(digits-1)))
		if magnitude.Cmp(big.NewInt(308)) > 0 {
			return 0, ErrRealOverflow
		}
		if magnitude.Cmp(big.NewInt(-325)) < 0 {
			return 0, ErrRealUnderflow
		}
		if !canonical.Exponent.IsInt64() {
			return 0, ErrInvalidReal
		}
		exponent := canonical.Exponent.Int64()
		if int64(int(exponent)) != exponent {
			return 0, ErrInvalidReal
		}
		power := new(big.Int).Exp(big.NewInt(10), big.NewInt(absInt64(exponent)), nil)
		factor := new(big.Float).SetPrec(precision).SetInt(power)
		if exponent < 0 {
			result.Quo(result, factor)
		} else {
			result.Mul(result, factor)
		}
	}

	converted, _ := result.Float64()
	if math.IsInf(converted, 0) {
		return 0, ErrRealOverflow
	}
	if converted == 0 {
		return 0, ErrRealUnderflow
	}
	return converted, nil
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
