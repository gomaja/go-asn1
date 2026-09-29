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
