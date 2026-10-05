package per

import (
	"fmt"
	"math"
)

const perFragmentUnit = 16 * 1024

// SizeConstraint describes the PER-visible root of a SIZE constraint.
type SizeConstraint struct {
	Lower      int64
	Upper      int64
	HasLower   bool
	HasUpper   bool
	Extensible bool
}

// EncodeLengthFragments writes the interleaved length determinants and value
// fragments required by ITU-T X.691 (02/2021), 11.9.3.8 and 11.9.4.
func EncodeLengthFragments(bb *BitBuffer, total int64, aligned bool, encodeFragment func(offset, length int64) error) error {
	if total < 0 {
		return fmt.Errorf("%w: negative fragmented length %d", ErrInvalidValue, total)
	}
	if encodeFragment == nil {
		return fmt.Errorf("%w: nil fragment encoder", ErrInvalidValue)
	}

	var offset int64
	for {
		if offset < 0 || offset > total {
			return fmt.Errorf("%w: fragmented offset %d exceeds length %d", ErrInvalidValue, offset, total)
		}
		length, more, err := encodeLengthFragmentDeterminant(bb, total-offset, aligned)
		if err != nil {
			return err
		}
		if length < 0 || length > total-offset {
			return fmt.Errorf("%w: fragment length %d exceeds remaining %d", ErrInvalidValue, length, total-offset)
		}
		if err := encodeFragment(offset, length); err != nil {
			return err
		}
		offset += length
		if !more {
			return nil
		}
	}
}

// DecodeLengthFragments reads interleaved PER length determinants and invokes
// decodeFragment once for each associated value fragment.
func DecodeLengthFragments(bb *BitBuffer, aligned bool, decodeFragment func(offset, length int64) error) (int64, error) {
	return decodeLengthFragmentsBounded(bb, aligned, math.MaxInt64, decodeFragment)
}

func decodeLengthFragmentsBounded(bb *BitBuffer, aligned bool, maximum int64, decodeFragment func(offset, length int64) error) (int64, error) {
	if maximum < 0 {
		return 0, fmt.Errorf("%w: negative fragmented length limit %d", ErrInvalidValue, maximum)
	}
	if decodeFragment == nil {
		return 0, fmt.Errorf("%w: nil fragment decoder", ErrInvalidValue)
	}

	var (
		offset                     int64
		previousFragmentMultiplier int
	)
	for {
		length, more, multiplier, err := decodeLengthFragmentDeterminant(bb, aligned)
		if err != nil {
			return 0, err
		}
		if more && previousFragmentMultiplier != 0 && previousFragmentMultiplier != 4 {
			return 0, fmt.Errorf("%w: non-maximal PER fragment multiplier %d", ErrInvalidValue, previousFragmentMultiplier)
		}
		if offset < 0 || length < 0 {
			return 0, fmt.Errorf("%w: negative fragmented offset %d or length %d", ErrInvalidValue, offset, length)
		}
		if length > math.MaxInt64-offset {
			return 0, fmt.Errorf("%w: fragmented length exceeds int64", ErrInvalidValue)
		}
		if offset > maximum {
			return 0, fmt.Errorf("%w: fragmented length %d exceeds upper bound %d", ErrConstraintViolation, offset+length, maximum)
		}
		if length > maximum-offset {
			return 0, fmt.Errorf("%w: fragmented length %d exceeds upper bound %d", ErrConstraintViolation, offset+length, maximum)
		}
		if err := decodeFragment(offset, length); err != nil {
			return 0, err
		}
		offset += length
		if !more {
			return offset, nil
		}
		previousFragmentMultiplier = multiplier
	}
}

// EncodeCollection writes a SEQUENCE OF or SET OF length and invokes
// encodeFragment for each interleaved group of elements.
func EncodeCollection(bb *BitBuffer, total int64, size SizeConstraint, aligned bool, encodeFragment func(offset, length int64) error) error {
	if err := size.validate(); err != nil {
		return err
	}
	if encodeFragment == nil {
		return fmt.Errorf("%w: nil collection fragment encoder", ErrInvalidValue)
	}
	if size.Extensible {
		inRoot := size.contains(total)
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return EncodeLengthFragments(bb, total, aligned, encodeFragment)
		}
	}
	if err := size.validateRoot(total); err != nil {
		return err
	}
	if size.HasUpper && size.Upper < 64*1024 {
		lower := int64(0)
		if size.HasLower {
			lower = size.Lower
		}
		if aligned {
			if err := EncodeConstrainedWholeNumberAligned(bb, total, lower, size.Upper); err != nil {
				return err
			}
		} else if err := EncodeConstrainedWholeNumber(bb, total, lower, size.Upper); err != nil {
			return err
		}
		return encodeFragment(0, total)
	}
	return EncodeLengthFragments(bb, total, aligned, encodeFragment)
}

// DecodeCollection reads a SEQUENCE OF or SET OF length and invokes
// decodeFragment for each interleaved group of elements.
func DecodeCollection(bb *BitBuffer, size SizeConstraint, aligned bool, decodeFragment func(offset, length int64) error) (int64, error) {
	if err := size.validate(); err != nil {
		return 0, err
	}
	if decodeFragment == nil {
		return 0, fmt.Errorf("%w: nil collection fragment decoder", ErrInvalidValue)
	}

	root := true
	if size.Extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		root = !isExtension
	}
	if root && size.HasUpper && size.Upper < 64*1024 {
		lower := int64(0)
		if size.HasLower {
			lower = size.Lower
		}
		var (
			length int64
			err    error
		)
		if aligned {
			length, err = DecodeConstrainedWholeNumberAligned(bb, lower, size.Upper)
		} else {
			length, err = DecodeConstrainedWholeNumber(bb, lower, size.Upper)
		}
		if err != nil {
			return 0, err
		}
		if err := decodeFragment(0, length); err != nil {
			return 0, err
		}
		return length, nil
	}

	maximum := int64(math.MaxInt64)
	if root && size.HasUpper {
		maximum = size.Upper
	}
	total, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(offset, length int64) error {
		return decodeFragment(offset, length)
	})
	if err != nil {
		return 0, err
	}
	if root {
		if err := size.validateRoot(total); err != nil {
			return 0, err
		}
	} else if size.contains(total) {
		return 0, fmt.Errorf("%w: extension collection length %d is inside the root %s", ErrInvalidValue, total, size)
	}
	return total, nil
}

func (size SizeConstraint) validate() error {
	if size.HasLower && size.Lower < 0 {
		return fmt.Errorf("%w: negative SIZE lower bound %d", ErrInvalidValue, size.Lower)
	}
	if size.HasUpper && size.Upper < 0 {
		return fmt.Errorf("%w: negative SIZE upper bound %d", ErrInvalidValue, size.Upper)
	}
	if size.HasLower && size.HasUpper && size.Lower > size.Upper {
		return fmt.Errorf("%w: invalid SIZE range [%d..%d]", ErrInvalidValue, size.Lower, size.Upper)
	}
	return nil
}

func (size SizeConstraint) contains(length int64) bool {
	return (!size.HasLower || length >= size.Lower) && (!size.HasUpper || length <= size.Upper)
}

func (size SizeConstraint) validateRoot(length int64) error {
	if !size.contains(length) {
		return fmt.Errorf("%w: collection length %d is outside its root %s", ErrConstraintViolation, length, size)
	}
	return nil
}

func encodeLengthFragmentDeterminant(bb *BitBuffer, remaining int64, aligned bool) (length int64, more bool, err error) {
	if remaining < 0 {
		return 0, false, fmt.Errorf("%w: negative remaining length %d", ErrInvalidValue, remaining)
	}
	if aligned {
		if err := bb.AlignToOctetWrite(); err != nil {
			return 0, false, err
		}
	}
	if remaining < perFragmentUnit {
		if err := EncodeUnconstrainedLength(bb, remaining); err != nil {
			return 0, false, err
		}
		return remaining, false, nil
	}

	multiplier := remaining / perFragmentUnit
	if multiplier > 4 {
		multiplier = 4
	}
	if multiplier < 1 || multiplier > 4 {
		return 0, false, fmt.Errorf("%w: invalid PER fragment multiplier %d", ErrInvalidValue, multiplier)
	}
	if err := bb.WriteBits(uint64(0xc0|multiplier), 8); err != nil {
		return 0, false, err
	}
	return multiplier * perFragmentUnit, true, nil
}

func decodeLengthFragmentDeterminant(bb *BitBuffer, aligned bool) (length int64, more bool, multiplier int, err error) {
	if aligned {
		if err := bb.AlignToOctetRead(); err != nil {
			return 0, false, 0, err
		}
	}
	first, err := bb.ReadBits(8)
	if err != nil {
		return 0, false, 0, err
	}
	if first > 0xff {
		return 0, false, 0, fmt.Errorf("%w: invalid PER length octet %d", ErrInvalidValue, first)
	}
	switch {
	case first&0x80 == 0:
		return int64(first), false, 0, nil
	case first&0xc0 == 0x80:
		second, err := bb.ReadBits(8)
		if err != nil {
			return 0, false, 0, err
		}
		if second <= 0xff {
			length := int64(first&0x3f)<<8 | int64(second)
			if length < 128 {
				return 0, false, 0, fmt.Errorf("%w: non-minimal PER length determinant", ErrInvalidValue)
			}
			return length, false, 0, nil
		}
		return 0, false, 0, fmt.Errorf("%w: invalid PER length octet %d", ErrInvalidValue, second)
	case first&0xc0 == 0xc0:
		multiplier := int(first & 0x3f)
		if multiplier >= 1 && multiplier <= 4 {
			return int64(multiplier * perFragmentUnit), true, multiplier, nil
		}
		return 0, false, 0, fmt.Errorf("%w: invalid PER fragment multiplier %d", ErrInvalidValue, multiplier)
	default:
		return 0, false, 0, fmt.Errorf("%w: invalid PER length determinant", ErrInvalidValue)
	}
}

func encodeLengthDelimitedOctets(bb *BitBuffer, data []byte, aligned bool) error {
	return EncodeLengthFragments(bb, int64(len(data)), aligned, func(offset, length int64) error {
		if offset < 0 || length < 0 || offset > int64(len(data)) {
			return fmt.Errorf("%w: fragment [%d:%d] exceeds %d octets", ErrInvalidValue, offset, length, len(data))
		}
		if length > int64(len(data))-offset {
			return fmt.Errorf("%w: fragment [%d:%d] exceeds %d octets", ErrInvalidValue, offset, length, len(data))
		}
		return bb.WriteBytes(data[int(offset):int(offset+length)])
	})
}

func decodeLengthDelimitedOctets(bb *BitBuffer, aligned bool) ([]byte, error) {
	return decodeLengthDelimitedOctetsBounded(bb, aligned, math.MaxInt64)
}

func decodeLengthDelimitedOctetsBounded(bb *BitBuffer, aligned bool, maximum int64) ([]byte, error) {
	result := []byte{} // present empty is not absent (go-asn1#91); no allocation
	_, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(_ int64, length int64) error {
		if length < 0 || length > int64(math.MaxInt) {
			return fmt.Errorf("%w: fragment length %d exceeds host int", ErrInvalidValue, length)
		}
		if int(length) > bb.BitsRemaining()/8 {
			return fmt.Errorf("%w: fragment requires %d octets with %d bits remaining", ErrTruncated, length, bb.BitsRemaining())
		}
		fragment, err := bb.ReadBytes(int(length))
		if err != nil {
			return err
		}
		result = append(result, fragment...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// String renders the effective root as X.680 (02/2021) 51.5 SIZE notation.
// An absent lower bound is 0 and an absent upper bound is MAX.
func (size SizeConstraint) String() string {
	lower, upper := int64(0), "MAX"
	if size.HasLower {
		lower = size.Lower
	}
	if size.HasUpper {
		upper = fmt.Sprint(size.Upper)
	}
	extension := ""
	if size.Extensible {
		extension = ", ..."
	}
	return fmt.Sprintf("SIZE(%d..%s%s)", lower, upper, extension)
}
