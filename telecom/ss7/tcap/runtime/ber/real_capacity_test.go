// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/real_capacity_test.go; SHA-256 4848f49c63b74cdf75d0383f749e6b3f0f5fe943c4395b8de755ff92e5b6b55e.
package ber

import (
	"errors"
	"math"
	"testing"
)

func TestDecimalRealCapacityHostBoundary(t *testing.T) {
	if got, err := decimalRealCapacity(math.MaxInt-4, 1); err != nil || got != math.MaxInt {
		t.Fatalf("exact boundary = %d, %v", got, err)
	}
	for _, tc := range []struct{ mantissa, exponent int }{
		{math.MaxInt - 3, 1}, {-1, 1}, {1, -1},
	} {
		if _, err := decimalRealCapacity(tc.mantissa, tc.exponent); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("decimalRealCapacity(%d,%d) = %v", tc.mantissa, tc.exponent, err)
		}
	}
}
