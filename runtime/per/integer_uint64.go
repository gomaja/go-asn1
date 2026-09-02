package per

import (
	"fmt"
	"math/bits"
)

// EncodeIntegerUint64 encodes a non-negative constrained INTEGER in UPER.
// See ITU-T X.691 (02/2021), clauses 11.5 and 13.1-13.2.
func EncodeIntegerUint64(bb *BitBuffer, value, lower, upper uint64, extensible bool) error {
	if lower > upper {
		return fmt.Errorf("%w: invalid uint64 range [%d..%d]", ErrInvalidValue, lower, upper)
	}
	inRoot := value >= lower && value <= upper
	if extensible {
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeUnconstrainedUint64(bb, value, false)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %d not in [%d..%d]", ErrConstraintViolation, value, lower, upper)
	}
	rangeValue := upper - lower
	if rangeValue == 0 {
		return nil
	}
	return bb.WriteBits(value-lower, bits.Len64(rangeValue))
}

// DecodeIntegerUint64 decodes a non-negative constrained INTEGER in UPER.
func DecodeIntegerUint64(bb *BitBuffer, lower, upper uint64, extensible bool) (uint64, error) {
	if lower > upper {
		return 0, fmt.Errorf("%w: invalid uint64 range [%d..%d]", ErrInvalidValue, lower, upper)
	}
	if extensible {
		outside, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if outside {
			return decodeUnconstrainedUint64(bb, false)
		}
	}
	rangeValue := upper - lower
	if rangeValue == 0 {
		return lower, nil
	}
	offset, err := bb.ReadBits(bits.Len64(rangeValue))
	if err != nil {
		return 0, err
	}
	if offset > rangeValue {
		return 0, fmt.Errorf("%w: constrained uint64 offset %d exceeds range %d", ErrInvalidValue, offset, rangeValue)
	}
	return lower + offset, nil
}

// EncodeIntegerUint64Aligned encodes a non-negative constrained INTEGER in APER.
// See ITU-T X.691 (02/2021), clauses 11.5 and 13.1-13.2.
func EncodeIntegerUint64Aligned(bb *BitBuffer, value, lower, upper uint64, extensible bool) error {
	if lower > upper {
		return fmt.Errorf("%w: invalid uint64 range [%d..%d]", ErrInvalidValue, lower, upper)
	}
	inRoot := value >= lower && value <= upper
	if extensible {
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeUnconstrainedUint64(bb, value, true)
		}
	} else if !inRoot {
		return fmt.Errorf("%w: %d not in [%d..%d]", ErrConstraintViolation, value, lower, upper)
	}
	rangeValue := upper - lower
	if rangeValue == 0 {
		return nil
	}
	offset := value - lower
	switch {
	case rangeValue < 255:
		return bb.WriteBits(offset, bits.Len64(rangeValue))
	case rangeValue == 255:
		bb.AlignToOctetWrite()
		return bb.WriteBits(offset, 8)
	case rangeValue < 65536:
		bb.AlignToOctetWrite()
		return bb.WriteBits(offset, 16)
	default:
		length := (bits.Len64(offset) + 7) / 8
		if length == 0 {
			length = 1
		}
		maximumLength := (bits.Len64(rangeValue) + 7) / 8
		if err := EncodeConstrainedWholeNumber(bb, int64(length), 1, int64(maximumLength)); err != nil {
			return err
		}
		bb.AlignToOctetWrite()
		for index := length - 1; index >= 0; index-- {
			if err := bb.WriteBits((offset>>(uint(index)*8))&0xff, 8); err != nil {
				return err
			}
		}
		return nil
	}
}

// DecodeIntegerUint64Aligned decodes a non-negative constrained INTEGER in APER.
func DecodeIntegerUint64Aligned(bb *BitBuffer, lower, upper uint64, extensible bool) (uint64, error) {
	if lower > upper {
		return 0, fmt.Errorf("%w: invalid uint64 range [%d..%d]", ErrInvalidValue, lower, upper)
	}
	if extensible {
		outside, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if outside {
			return decodeUnconstrainedUint64(bb, true)
		}
	}
	rangeValue := upper - lower
	if rangeValue == 0 {
		return lower, nil
	}
	var offset uint64
	var err error
	switch {
	case rangeValue < 255:
		offset, err = bb.ReadBits(bits.Len64(rangeValue))
	case rangeValue == 255:
		bb.AlignToOctetRead()
		offset, err = bb.ReadBits(8)
	case rangeValue < 65536:
		bb.AlignToOctetRead()
		offset, err = bb.ReadBits(16)
	default:
		maximumLength := (bits.Len64(rangeValue) + 7) / 8
		var length int64
		length, err = DecodeConstrainedWholeNumber(bb, 1, int64(maximumLength))
		if err == nil {
			bb.AlignToOctetRead()
			var data []byte
			data, err = bb.ReadBytes(int(length))
			if err == nil {
				err = validateMinimalUnsigned(data)
			}
			if err == nil {
				for _, item := range data {
					offset = offset<<8 | uint64(item)
				}
			}
		}
	}
	if err != nil {
		return 0, err
	}
	if offset > rangeValue {
		return 0, fmt.Errorf("%w: constrained uint64 offset %d exceeds range %d", ErrInvalidValue, offset, rangeValue)
	}
	return lower + offset, nil
}

func encodeUnconstrainedUint64(bb *BitBuffer, value uint64, aligned bool) error {
	data := minimalUnsignedBytes(value)
	if data[0]&0x80 != 0 {
		data = append([]byte{0}, data...)
	}
	if aligned {
		if err := EncodeUnconstrainedLengthAligned(bb, int64(len(data))); err != nil {
			return err
		}
	} else if err := EncodeUnconstrainedLength(bb, int64(len(data))); err != nil {
		return err
	}
	return bb.WriteBytes(data)
}

func decodeUnconstrainedUint64(bb *BitBuffer, aligned bool) (uint64, error) {
	var length int64
	var err error
	if aligned {
		length, err = DecodeUnconstrainedLengthAligned(bb)
	} else {
		length, err = DecodeUnconstrainedLength(bb)
	}
	if err != nil {
		return 0, err
	}
	if length < 1 || length > 9 {
		return 0, fmt.Errorf("%w: uint64 INTEGER length %d", ErrInvalidValue, length)
	}
	data, err := bb.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}
	if data[0]&0x80 != 0 || len(data) == 9 && data[0] != 0 {
		return 0, fmt.Errorf("%w: INTEGER is negative or exceeds uint64", ErrInvalidValue)
	}
	if len(data) > 1 && data[0] == 0 && data[1]&0x80 == 0 {
		return 0, fmt.Errorf("%w: INTEGER has redundant leading zero octet", ErrInvalidValue)
	}
	if len(data) == 9 {
		data = data[1:]
	}
	var value uint64
	for _, item := range data {
		value = value<<8 | uint64(item)
	}
	return value, nil
}
