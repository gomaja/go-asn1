// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/real_test.go; SHA-256 9b2375a1368a2cdce8d7f4c60af52c5e94e0bb23b31d90be4bc1a5728948ad67.
package runtime

import (
	"errors"
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
