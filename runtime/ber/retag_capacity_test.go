package ber

import (
	"errors"
	"math"
	"testing"
)

func TestRetagCapacityHostBoundary(t *testing.T) {
	if got, err := retagCapacity(1, math.MaxInt, 1); err != nil || got != math.MaxInt {
		t.Fatalf("exact boundary = %d, %v", got, err)
	}
	for _, tc := range []struct{ replacement, content, tag int }{
		{2, math.MaxInt, 1}, {1, 0, 1}, {-1, 2, 1}, {1, 2, -1},
	} {
		if _, err := retagCapacity(tc.replacement, tc.content, tc.tag); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("retagCapacity(%d,%d,%d) = %v", tc.replacement, tc.content, tc.tag, err)
		}
	}
}
