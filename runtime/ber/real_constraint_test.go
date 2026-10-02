package ber

import (
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func TestRealAllowedExactCrossBaseAndSpecialOrdering(t *testing.T) {
	ranges := []RealRange{{
		Lower: RealBound{Base: 10, Mantissa: "15", Exponent: "-1"},
		Upper: RealBound{Base: 10, Mantissa: "35", Exponent: "-1"},
	}}
	for _, item := range []struct {
		mantissa int64
		exponent int64
		allowed  bool
	}{
		{3, -1, true},   // 1.5 in binary: inclusive lower endpoint.
		{7, -1, true},   // 3.5 in binary: inclusive upper endpoint.
		{5, -2, false},  // 1.25, below the lower endpoint.
		{15, -2, false}, // 3.75, above the upper endpoint.
	} {
		value, err := runtime.NewReal(2, big.NewInt(item.mantissa), big.NewInt(item.exponent))
		if err != nil {
			t.Fatal(err)
		}
		allowed, err := RealAllowed(value, ranges)
		if err != nil || allowed != item.allowed {
			t.Fatalf("REAL %s: allowed=%t error=%v, want %t", RealConstraintValue(value), allowed, err, item.allowed)
		}
	}
	minusZero, err := runtime.NewSpecialReal(runtime.RealMinusZero)
	if err != nil {
		t.Fatal(err)
	}
	zeroRange := []RealRange{{Lower: RealBound{Kind: runtime.RealMinusZero}, Upper: RealBound{Base: 2, Mantissa: "0", Exponent: "0"}}}
	allowed, err := RealAllowed(minusZero, zeroRange)
	if err != nil || !allowed {
		t.Fatalf("minus zero range: allowed=%t error=%v", allowed, err)
	}
	allowed, err = RealAllowed(runtime.Real{}, zeroRange)
	if err != nil || !allowed {
		t.Fatalf("plus zero range: allowed=%t error=%v", allowed, err)
	}
	allowed, err = RealAllowed(minusZero, ranges)
	if err != nil || allowed {
		t.Fatalf("minus zero in positive range: allowed=%t error=%v", allowed, err)
	}
	if _, err := RealAllowed(runtime.Real{}, []RealRange{{
		Lower: RealBound{Base: 2, Mantissa: "5", Exponent: "0"},
		Upper: RealBound{Base: 2, Mantissa: "1", Exponent: "0"},
	}}); err == nil {
		t.Fatal("accepted inverted REAL range")
	}
}
