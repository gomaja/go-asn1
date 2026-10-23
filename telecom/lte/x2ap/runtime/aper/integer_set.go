// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_set.go; SHA-256 47d1529f711ab96fc99cc28f5cdd8f9cea6735515816aea2647ec52fa47af651.
package aper

import "fmt"

// IntegerRange is one inclusive root interval of a finite INTEGER value set.
type IntegerRange struct {
	Min int64
	Max int64
}

func integerSetBounds(value int64, ranges []IntegerRange) (int64, int64, bool, error) {
	if len(ranges) == 0 {
		return 0, 0, false, fmt.Errorf("%w: INTEGER value set is empty", ErrInvalidValue)
	}
	for index, item := range ranges {
		if item.Min > item.Max {
			return 0, 0, false, fmt.Errorf("%w: invalid INTEGER value-set range [%d..%d]", ErrInvalidValue, item.Min, item.Max)
		}
		if index > 0 {
			if item.Min <= ranges[index-1].Max {
				return 0, 0, false, fmt.Errorf("%w: INTEGER value-set ranges overlap or are unsorted", ErrInvalidValue)
			}
		}
	}
	return ranges[0].Min, ranges[len(ranges)-1].Max, integerSetContains(value, ranges), nil
}

func integerSetContains(value int64, ranges []IntegerRange) bool {
	for _, item := range ranges {
		if value >= item.Min && value <= item.Max {
			return true
		}
	}
	return false
}
