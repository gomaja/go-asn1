package per

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
