// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_capacity_test.go; SHA-256 3dabac02d70432b0ce4cc79ee09a0bd1d6e3688619bd0dc13afe9df0c3e3bb00.
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
