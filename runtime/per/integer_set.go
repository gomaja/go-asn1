package per

import "fmt"

// IntegerRange is one inclusive root interval of a finite INTEGER value set.
type IntegerRange struct {
	Min int64
	Max int64
}

// EncodeIntegerValueSet encodes an INTEGER constrained by a finite root set.
func EncodeIntegerValueSet(bb *BitBuffer, value int64, ranges []IntegerRange, extensible bool) error {
	minimum, maximum, inRoot, err := integerSetBounds(value, ranges)
	if err != nil {
		return err
	}
	if extensible {
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return EncodeUnconstrainedWholeNumber(bb, value)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %d is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return EncodeConstrainedWholeNumber(bb, value, minimum, maximum)
}

// DecodeIntegerValueSet decodes and validates an INTEGER finite root set.
func DecodeIntegerValueSet(bb *BitBuffer, ranges []IntegerRange, extensible bool) (int64, error) {
	minimum, maximum, _, err := integerSetBounds(0, ranges)
	if err != nil {
		return 0, err
	}
	if extensible {
		outside, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if outside {
			return DecodeUnconstrainedWholeNumber(bb)
		}
	}
	value, err := DecodeConstrainedWholeNumber(bb, minimum, maximum)
	if err != nil {
		return 0, err
	}
	if !integerSetContains(value, ranges) {
		return 0, fmt.Errorf("%w: decoded root value %d is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return value, nil
}

// EncodeIntegerValueSetAligned is the APER form of EncodeIntegerValueSet.
func EncodeIntegerValueSetAligned(bb *BitBuffer, value int64, ranges []IntegerRange, extensible bool) error {
	minimum, maximum, inRoot, err := integerSetBounds(value, ranges)
	if err != nil {
		return err
	}
	if extensible {
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return EncodeUnconstrainedWholeNumberAligned(bb, value)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %d is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return EncodeConstrainedWholeNumberAligned(bb, value, minimum, maximum)
}

// DecodeIntegerValueSetAligned is the APER form of DecodeIntegerValueSet.
func DecodeIntegerValueSetAligned(bb *BitBuffer, ranges []IntegerRange, extensible bool) (int64, error) {
	minimum, maximum, _, err := integerSetBounds(0, ranges)
	if err != nil {
		return 0, err
	}
	if extensible {
		outside, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if outside {
			return DecodeUnconstrainedWholeNumberAligned(bb)
		}
	}
	value, err := DecodeConstrainedWholeNumberAligned(bb, minimum, maximum)
	if err != nil {
		return 0, err
	}
	if !integerSetContains(value, ranges) {
		return 0, fmt.Errorf("%w: decoded root value %d is outside the permitted INTEGER value set", ErrConstraintViolation, value)
	}
	return value, nil
}

func integerSetBounds(value int64, ranges []IntegerRange) (int64, int64, bool, error) {
	if len(ranges) == 0 {
		return 0, 0, false, fmt.Errorf("%w: INTEGER value set is empty", ErrInvalidValue)
	}
	for index, item := range ranges {
		if item.Min > item.Max {
			return 0, 0, false, fmt.Errorf("%w: invalid INTEGER value-set range [%d..%d]", ErrInvalidValue, item.Min, item.Max)
		}
		if index != 0 && item.Min <= ranges[index-1].Max {
			return 0, 0, false, fmt.Errorf("%w: INTEGER value-set ranges overlap or are unsorted", ErrInvalidValue)
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
