// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/big_width_test.go; SHA-256 3f7ec28bf9cd3b9e2b3e9ac5d932fa3f9fe2484c130e346ae2136a770e8d4188.
package aper

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

func TestConstrainedBigMaximumLengthHostBoundary(t *testing.T) {
	if got, err := constrainedBigMaximumLength(math.MaxInt); err != nil || got != math.MaxInt/8+1 {
		t.Fatalf("maximum bit count = %d octets, %v", got, err)
	}
	if _, err := constrainedBigMaximumLength(-1); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("negative bit count accepted: %v", err)
	}
}
