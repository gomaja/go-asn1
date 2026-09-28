package ber

import (
	"errors"
	"math"
	"testing"
)

func TestFixedWidthStringCapacityRejectsHostOverflow(t *testing.T) {
	for _, width := range []int{2, 4} {
		if got, err := fixedWidthStringCapacity(math.MaxInt/width, width); err != nil || got != math.MaxInt/width*width {
			t.Errorf("width %d exact boundary = %d, %v", width, got, err)
		}
		if _, err := fixedWidthStringCapacity(math.MaxInt/width+1, width); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("width %d overflow: %v", width, err)
		}
	}
}
