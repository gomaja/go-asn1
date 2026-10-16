package ber

import (
	"math/big"
	"testing"

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
	// Squared powers use logarithmically many divisions. Bound quotient
	// allocations, and retain the scan fallback for a per-factor loop that
	// reuses its quotient storage instead of allocating it each time.
	var previousTime, previousExponent int64
	for _, exponent := range []int64{1024, 4096, 16384, 65536, 100000} {
		mantissa := new(big.Int).Exp(big.NewInt(5), big.NewInt(exponent), nil)
		value := runtime.Real{Kind: runtime.RealFinite, Base: 2, Mantissa: mantissa, Exponent: big.NewInt(0)}
		operation := func() {
			equal, err := RealEqualsDERDefault(value, string(defaultDER))
			if err != nil || equal {
				t.Fatalf("equality = %t, %v; want false", equal, err)
			}
		}
		allocated, allocations := allocationCost(t, 5, operation)
		if allocated > uint64(64*exponent+8192) || allocations > 256 {
			t.Fatalf("5^%d: %d bytes, %d allocations", exponent, allocated, allocations)
		}
		elapsed := minimumTime(t, operation).Nanoseconds()
		if previousTime != 0 && elapsed*previousExponent > 3*previousTime*exponent {
			t.Fatalf("5^%d: %d ns, previous 5^%d: %d ns; exceeds linear bound", exponent, elapsed, previousExponent, previousTime)
		}
		previousTime, previousExponent = elapsed, exponent
		t.Logf("5^%d: %d bytes, %d allocations, minimum %d ns", exponent, allocated, allocations, elapsed)
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
