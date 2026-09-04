package runtime

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

func TestNewRealNormalizesFiniteValues(t *testing.T) {
	tests := []struct {
		name     string
		base     int
		mantissa string
		exponent string
		wantMant string
		wantExp  string
	}{
		{name: "binary positive", base: 2, mantissa: "40", exponent: "-5", wantMant: "5", wantExp: "-2"},
		{name: "binary negative", base: 2, mantissa: "-24", exponent: "7", wantMant: "-3", wantExp: "10"},
		{name: "decimal positive", base: 10, mantissa: "12500", exponent: "-3", wantMant: "125", wantExp: "-1"},
		{name: "decimal negative", base: 10, mantissa: "-9000", exponent: "2", wantMant: "-9", wantExp: "5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewReal(test.base, mustBigInt(t, test.mantissa), mustBigInt(t, test.exponent))
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != RealFinite || got.Base != test.base || got.Mantissa.String() != test.wantMant || got.Exponent.String() != test.wantExp {
				t.Fatalf("NewReal() = %#v, want base=%d mantissa=%s exponent=%s", got, test.base, test.wantMant, test.wantExp)
			}
		})
	}
}

func TestRealValidationRejectsInvalidStates(t *testing.T) {
	tests := []Real{
		{Kind: RealKind(99)},
		{Kind: RealFinite, Base: 3, Mantissa: big.NewInt(1), Exponent: big.NewInt(0)},
		{Kind: RealFinite, Base: 2, Mantissa: big.NewInt(1)},
		{Kind: RealPlusInfinity, Mantissa: big.NewInt(1)},
	}
	for _, value := range tests {
		if err := value.Validate(); !errors.Is(err, ErrInvalidReal) {
			t.Errorf("%#v validation error = %v, want ErrInvalidReal", value, err)
		}
	}
}

func TestRealFloat64Conversions(t *testing.T) {
	for _, value := range []float64{0, math.Copysign(0, -1), 1, -2.5, math.SmallestNonzeroFloat64, math.MaxFloat64, math.Inf(1), math.Inf(-1), math.NaN()} {
		realValue := NewRealFromFloat64(value)
		got, err := realValue.Float64()
		if err != nil {
			t.Fatalf("Float64(%v): %v", value, err)
		}
		if math.IsNaN(value) {
			if !math.IsNaN(got) {
				t.Fatalf("Float64(NaN) = %v", got)
			}
			continue
		}
		if math.Float64bits(got) != math.Float64bits(value) {
			t.Fatalf("Float64(%v) bits = %x, want %x", value, math.Float64bits(got), math.Float64bits(value))
		}
	}

	overflow, err := NewReal(10, big.NewInt(1), big.NewInt(10000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overflow.Float64(); !errors.Is(err, ErrRealOverflow) {
		t.Fatalf("overflow error = %v, want ErrRealOverflow", err)
	}
	underflow, err := NewReal(10, big.NewInt(1), big.NewInt(-10000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := underflow.Float64(); !errors.Is(err, ErrRealUnderflow) {
		t.Fatalf("underflow error = %v, want ErrRealUnderflow", err)
	}
}

func TestNewRealCopiesInputs(t *testing.T) {
	mantissa := big.NewInt(3)
	exponent := big.NewInt(4)
	value, err := NewReal(2, mantissa, exponent)
	if err != nil {
		t.Fatal(err)
	}
	mantissa.SetInt64(99)
	exponent.SetInt64(99)
	if value.Mantissa.String() != "3" || value.Exponent.String() != "4" {
		t.Fatalf("NewReal retained caller-owned integers: %#v", value)
	}
}

func mustBigInt(t *testing.T, value string) *big.Int {
	t.Helper()
	result, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid big integer %q", value)
	}
	return result
}
