package ber

import (
	"errors"
	"math"
	"testing"
)

func TestBitStringBitLengthHostBoundary(t *testing.T) {
	octets := math.MaxInt/8 + 1
	if got, err := BitStringBitLength(octets, 1); err != nil || got != math.MaxInt {
		t.Fatalf("exact host boundary: got %d, %v", got, err)
	}
	if _, err := BitStringBitLength(octets, 0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("past host boundary: got %v, want ErrInvalidValue", err)
	}
	for _, tc := range []struct{ octets, unused int }{
		{-1, 0}, {0, 1}, {1, -1}, {1, 8}, {octets + 1, 7},
	} {
		if _, err := BitStringBitLength(tc.octets, tc.unused); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("BitStringBitLength(%d, %d): %v", tc.octets, tc.unused, err)
		}
	}
	if got, err := BitStringBitLength(0, 0); err != nil || got != 0 {
		t.Fatalf("empty bit string: got %d, %v", got, err)
	}
}
