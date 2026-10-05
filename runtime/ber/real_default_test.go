package ber

import (
	"math/big"
	"testing"
	"time"

	"github.com/gomaja/go-asn1/runtime"
)

func TestRealEqualsDERDefaultAcrossBases(t *testing.T) {
	decimal, err := runtime.NewReal(10, big.NewInt(15), big.NewInt(-1))
	if err != nil {
		t.Fatal(err)
	}
	defaultDER, err := EncodeReal(decimal)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value runtime.Real
		want  bool
	}{
		{"decimal", decimal, true},
		{"binary", mustTestReal(t, 2, 3, -1), true},
		{"different", mustTestReal(t, 2, 5, -1), false},
		{"negative", mustTestReal(t, 2, -3, -1), false},
		{"infinity", runtime.Real{Kind: runtime.RealPlusInfinity}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RealEqualsDERDefault(tc.value, string(defaultDER))
			if err != nil || got != tc.want {
				t.Fatalf("equal = %t, %v; want %t", got, err, tc.want)
			}
		})
	}
	if _, err := RealEqualsDERDefault(decimal, string(defaultDER)+"x"); err == nil {
		t.Fatal("accepted trailing data in REAL DEFAULT")
	}
}

func TestRealEqualsDERDefaultLargePowerOfFive(t *testing.T) {
	defaultDER, err := EncodeReal(runtime.Real{Kind: runtime.RealFinite, Base: 2, Mantissa: big.NewInt(1), Exponent: big.NewInt(0)})
	if err != nil {
		t.Fatal(err)
	}
	// A per-factor division takes roughly a second for 5^100000 on the
	// pre-fix implementation. Batched extraction needs logarithmically many
	// divisions even when the mantissa is supplied by a caller.
	mantissa := new(big.Int).Exp(big.NewInt(5), big.NewInt(100000), nil)
	value := runtime.Real{Kind: runtime.RealFinite, Base: 2, Mantissa: mantissa, Exponent: big.NewInt(0)}
	start := time.Now()
	equal, err := RealEqualsDERDefault(value, string(defaultDER))
	if err != nil || equal {
		t.Fatalf("equality = %t, %v; want false", equal, err)
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("factor extraction took %s for 5^100000", elapsed)
	}
}

func TestRealEqualsDERDefaultLargeExactCrossBaseValue(t *testing.T) {
	const exponent = 10000
	mantissa := new(big.Int).Exp(big.NewInt(5), big.NewInt(exponent), nil)
	decimal := runtime.Real{Kind: runtime.RealFinite, Base: 10, Mantissa: mantissa, Exponent: big.NewInt(-exponent)}
	binary := runtime.Real{Kind: runtime.RealFinite, Base: 2, Mantissa: big.NewInt(1), Exponent: big.NewInt(-exponent)}
	defaultDER, err := EncodeReal(binary)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := RealEqualsDERDefault(decimal, string(defaultDER))
	if err != nil || !equal {
		t.Fatalf("equal = %t, %v; want true", equal, err)
	}
}

func mustTestReal(t *testing.T, base int, mantissa, exponent int64) runtime.Real {
	t.Helper()
	value, err := runtime.NewReal(base, big.NewInt(mantissa), big.NewInt(exponent))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
