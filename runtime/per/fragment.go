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
		length, more, err := encodeLengthFragmentDeterminant(bb, total-offset, aligned)
		if err != nil {
			return err
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
		if length > math.MaxInt64-offset {
			return 0, fmt.Errorf("%w: fragmented length exceeds int64", ErrInvalidValue)
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

	total, err := DecodeLengthFragments(bb, aligned, func(offset, length int64) error {
		if root && size.HasUpper && (offset > size.Upper || length > size.Upper-offset) {
			return fmt.Errorf("%w: collection length exceeds upper bound %d", ErrConstraintViolation, size.Upper)
		}
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
		return 0, fmt.Errorf("%w: extension collection length %d is inside the root", ErrInvalidValue, total)
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
		return fmt.Errorf("%w: collection length %d is outside its root SIZE constraint", ErrConstraintViolation, length)
	}
	return nil
}

func encodeLengthFragmentDeterminant(bb *BitBuffer, remaining int64, aligned bool) (length int64, more bool, err error) {
	if remaining < 0 {
		return 0, false, fmt.Errorf("%w: negative remaining length %d", ErrInvalidValue, remaining)
	}
	if aligned {
		bb.AlignToOctetWrite()
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
	if err := bb.WriteBits(uint64(0xc0|multiplier), 8); err != nil {
		return 0, false, err
	}
	return multiplier * perFragmentUnit, true, nil
}

func decodeLengthFragmentDeterminant(bb *BitBuffer, aligned bool) (length int64, more bool, multiplier int, err error) {
	if aligned {
		bb.AlignToOctetRead()
	}
	first, err := bb.ReadBits(8)
	if err != nil {
		return 0, false, 0, err
	}
	switch {
	case first&0x80 == 0:
		return int64(first), false, 0, nil
	case first&0xc0 == 0x80:
		second, err := bb.ReadBits(8)
		if err != nil {
			return 0, false, 0, err
		}
		length := int64(first&0x3f)<<8 | int64(second)
		if length < 128 {
			return 0, false, 0, fmt.Errorf("%w: non-minimal PER length determinant", ErrInvalidValue)
		}
		return length, false, 0, nil
	case first&0xc0 == 0xc0:
		multiplier := int(first & 0x3f)
		if multiplier < 1 || multiplier > 4 {
			return 0, false, 0, fmt.Errorf("%w: invalid PER fragment multiplier %d", ErrInvalidValue, multiplier)
		}
		return int64(multiplier * perFragmentUnit), true, multiplier, nil
	default:
		return 0, false, 0, fmt.Errorf("%w: invalid PER length determinant", ErrInvalidValue)
	}
}

func encodeLengthDelimitedOctets(bb *BitBuffer, data []byte, aligned bool) error {
	return EncodeLengthFragments(bb, int64(len(data)), aligned, func(offset, length int64) error {
		return bb.WriteBytes(data[int(offset):int(offset+length)])
	})
}

func decodeLengthDelimitedOctets(bb *BitBuffer, aligned bool) ([]byte, error) {
	var result []byte
	_, err := DecodeLengthFragments(bb, aligned, func(_ int64, length int64) error {
		if length > int64(bb.BitsRemaining()/8) {
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
