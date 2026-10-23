// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/big_width_test.go; SHA-256 92ae11c87b5d56fa7249dee3105451f8096bd44c46ca47ba04e85e31da79105c.
package uper

import (
	"errors"
	"math"
	"testing"
)

func TestNegativeTwosComplementWidthHostBoundary(t *testing.T) {
	if got, err := negativeTwosComplementWidth(math.MaxInt - 8); err != nil || got != math.MaxInt/8 {
		t.Fatalf("exact host boundary = %d, %v", got, err)
	}
	for _, bitLen := range []int{-1, math.MaxInt - 7, math.MaxInt} {
		if _, err := negativeTwosComplementWidth(bitLen); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("bit length %d: %v", bitLen, err)
		}
	}
}
