// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/charstring.go; SHA-256 c76a23a743d636208af656a84e7224493c1290ef8ddef2f92821b3bde44cd2ac.
package uper

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// characterCodec is the character encoding of ITU-T X.691 (02/2021) 30.5.2
// to 30.5.5 for unaligned PER.
type characterCodec struct {
	// bits is B in the UNALIGNED variant (30.5.2).
	bits int
	// valueBits bounds the whole-alphabet character values: every
	// value below 2 to the power valueBits is a character.
	valueBits int
	// wide marks strings held as UTF-8 runes; otherwise each octet of the Go
	// string is one character.
	wide bool
}

// identityCharacterCodec covers a type's whole alphabet when all its values
// fit in alphabetBits, which is B of 30.5.2.
func identityCharacterCodec(alphabetBits int, aligned bool) (characterCodec, error) {
	if err := validateKnownMultiplierWidth(alphabetBits); err != nil {
		return characterCodec{}, err
	}
	width := alphabetBits

	return characterCodec{bits: width, valueBits: alphabetBits, wide: alphabetBits > 8}, nil
}

func validateKnownMultiplierWidth(bitsPerChar int) error {
	if bitsPerChar < 1 || bitsPerChar > 32 {
		return fmt.Errorf("%w: character width %d bits is outside [1..32]", ErrInvalidValue, bitsPerChar)
	}
	return nil
}

// encodeValue maps a character value to the bits written for it.
func (codec characterCodec) encodeValue(value uint32) (uint64, error) {
	{
		if uint64(value) >= uint64(1)<<codec.valueBits {
			return 0, fmt.Errorf("%w: character %#x does not fit in %d bits", ErrConstraintViolation, value, codec.valueBits)
		}
		return uint64(value), nil
	}
}

// decodeValue maps the bits read for a character to its value.
func (codec characterCodec) decodeValue(code uint64) (uint32, error) {
	{
		if code >= uint64(1)<<codec.valueBits {
			return 0, fmt.Errorf("%w: character %#x does not fit in %d bits", ErrInvalidValue, code, codec.valueBits)
		}
		return uint32(code), nil
	}
}

// length validates every character of value and returns the character count.
func (codec characterCodec) length(value string) (int64, error) {
	if !codec.wide {
		for index := 0; index < len(value); index++ {
			if _, err := codec.encodeValue(uint32(value[index])); err != nil {
				return 0, err
			}
		}
		return int64(len(value)), nil
	}
	if !utf8.ValidString(value) {
		return 0, fmt.Errorf("%w: wide character string is not valid UTF-8", ErrInvalidValue)
	}
	var count int64
	for _, character := range value {
		if _, err := codec.encodeValue(uint32(character)); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

// payloadBits returns length times b, the size of the character bit-field.
func (codec characterCodec) payloadBits(length int64) (int, error) {
	if length < 0 {
		return 0, fmt.Errorf("%w: negative character-string length %d", ErrInvalidValue, length)
	}
	if codec.bits < 0 || codec.bits > 32 {
		return 0, fmt.Errorf("%w: character width %d bits is outside [0..32]", ErrInvalidValue, codec.bits)
	}
	if codec.bits == 0 {
		return 0, nil
	}
	maximumInt := int64(^uint(0) >> 1)
	if length > maximumInt/int64(codec.bits) {
		return 0, fmt.Errorf("%w: character-string payload length overflows int", ErrInvalidValue)
	}
	return int(length) * codec.bits, nil
}

// write appends the characters of an already validated value.
func (codec characterCodec) write(bb *BitBuffer, value string) error {
	if !codec.wide {
		for index := 0; index < len(value); index++ {
			code, err := codec.encodeValue(uint32(value[index]))
			if err != nil {
				return err
			}
			if err := bb.WriteBits(code, codec.bits); err != nil {
				return err
			}
		}
		return nil
	}
	for _, character := range value {
		code, err := codec.encodeValue(uint32(character))
		if err != nil {
			return err
		}
		if err := bb.WriteBits(code, codec.bits); err != nil {
			return err
		}
	}
	return nil
}

// read decodes length characters after checking that their bits are present.
func (codec characterCodec) read(bb *BitBuffer, length int64) (string, error) {
	payloadBits, err := codec.payloadBits(length)
	if err != nil {
		return "", err
	}
	if payloadBits > bb.BitsRemaining() {
		return "", fmt.Errorf("%w: character string requires %d bits with %d remaining", ErrTruncated, payloadBits, bb.BitsRemaining())
	}
	if length > int64(math.MaxInt) {
		return "", fmt.Errorf("%w: character string length exceeds host int", ErrInvalidValue)
	}
	if !codec.wide {
		result := make([]byte, int(length))
		for index := range result {
			code, err := bb.ReadBits(codec.bits)
			if err != nil {
				return "", err
			}
			value, err := codec.decodeValue(code)
			if err != nil {
				return "", err
			}
			if value > math.MaxUint8 {
				return "", fmt.Errorf("%w: character exceeds byte", ErrInvalidValue)
			}
			result[index] = byte(value)
		}
		return string(result), nil
	}
	result := make([]rune, int(length))
	for index := range result {
		code, err := bb.ReadBits(codec.bits)
		if err != nil {
			return "", err
		}
		value, err := codec.decodeValue(code)
		if err != nil {
			return "", err
		}
		if value > math.MaxInt32 || !utf8.ValidRune(rune(value)) {
			return "", fmt.Errorf("%w: invalid Unicode scalar value U+%X", ErrInvalidValue, value)
		}
		result[index] = rune(value)
	}
	return string(result), nil
}

// encodeCharacterString implements ITU-T X.691 (02/2021) 30.4 to 30.5.7.
func encodeCharacterString(bb *BitBuffer, value string, codec characterCodec, lb, ub int64, constrained, extensible, aligned bool) error {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return err
	}
	length, err := codec.length(value)
	if err != nil {
		return err
	}
	if extensible && constrained {
		inRoot := length >= lb && length <= ub
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return encodeLengthDelimitedCharacters(bb, value, length, codec, false)
		}
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return err
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {

		return codec.write(bb, value)
	}
	if !constrained || ub >= 65536 {
		return encodeLengthDelimitedCharacters(bb, value, length, codec, false)
	}

	{
		err = EncodeConstrainedWholeNumber(bb, length, lb, ub)
	}
	if err != nil {
		return err
	}
	// X.691 (02/2021) 11.9.3.3: nothing, not even padding, follows a zero
	// length.
	if length == 0 {
		return nil
	}

	return codec.write(bb, value)
}

// decodeCharacterString mirrors encodeCharacterString.
func decodeCharacterString(bb *BitBuffer, codec characterCodec, lb, ub int64, constrained, extensible, aligned bool) (string, error) {
	if err := validateSizeBounds(lb, ub, constrained); err != nil {
		return "", err
	}
	if extensible && constrained {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return "", err
		}
		if isExtension {
			value, decodedLength, err := decodeLengthDelimitedCharacters(bb, codec, false, math.MaxInt64)
			if err != nil {
				return "", err
			}
			// 30.4 sets the bit only for a length outside the root, so a root
			// length in extension form cannot be re-encoded as received.
			if decodedLength >= lb && decodedLength <= ub {
				return "", fmt.Errorf("%w: extension character-string length %d is inside the root SIZE(%d..%d)", ErrInvalidValue, decodedLength, lb, ub)
			}
			return value, nil
		}
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {

		return codec.read(bb, lb)
	}
	if !constrained || ub >= 65536 {
		value, decodedLength, err := decodeLengthDelimitedCharacters(bb, codec, false, rootSizeMaximum(ub, constrained))
		if err != nil {
			return "", err
		}
		if err := validateRootSize(decodedLength, lb, ub, constrained); err != nil {
			return "", err
		}
		return value, nil
	}
	var length int64
	var err error

	{
		length, err = DecodeConstrainedWholeNumber(bb, lb, ub)
	}
	if err != nil {
		return "", err
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}

	return codec.read(bb, length)
}

// encodeLengthDelimitedCharacters adds the characters with a length
// determinant counting characters (X.691 (02/2021) 11.9 and 30.5.7),
// fragmenting at 16K characters.
func encodeLengthDelimitedCharacters(bb *BitBuffer, value string, length int64, codec characterCodec, aligned bool) error {
	var runes []rune
	limit := int64(len(value))
	if codec.wide {
		runes = []rune(value)
		limit = int64(len(runes))
	}
	if length != limit {
		return fmt.Errorf("%w: character count %d does not match %d source characters", ErrInvalidValue, length, limit)
	}
	return EncodeLengthFragments(bb, length, false, func(offset, fragmentLength int64) error {

		if offset < 0 || fragmentLength < 0 {
			return fmt.Errorf("%w: negative character fragment offset %d or length %d", ErrInvalidValue, offset, fragmentLength)
		}
		if offset > limit {
			return fmt.Errorf("%w: character fragment at %d with %d characters exceeds %d source characters", ErrInvalidValue, offset, fragmentLength, limit)
		}
		if fragmentLength > limit-offset {
			return fmt.Errorf("%w: character fragment at %d with %d characters exceeds %d source characters", ErrInvalidValue, offset, fragmentLength, limit)
		}
		end := offset + fragmentLength
		if end < 0 || end > int64(math.MaxInt) {
			return fmt.Errorf("%w: character fragment exceeds host int", ErrInvalidValue)
		}
		if !codec.wide {
			return codec.write(bb, value[int(offset):int(end)])
		}
		return codec.write(bb, string(runes[int(offset):int(end)]))
	})
}

func decodeLengthDelimitedCharacters(bb *BitBuffer, codec characterCodec, aligned bool, maximum int64) (string, int64, error) {
	var result strings.Builder
	zeroWidthLimit := bb.zeroWidthCharacterLimit()
	total, err := decodeLengthFragmentsBounded(bb, false, maximum, func(offset int64, length int64) error {
		// Zero-bit characters consume no input, so only this operational
		// limit bounds a decoded length that X.691 (02/2021) 11.9 leaves
		// unbounded. Schema-bounded lengths below 64K never reach it.
		if codec.bits == 0 && length > zeroWidthLimit-offset {
			return fmt.Errorf("%w: %d zero-bit characters after %d exceed the limit of %d", ErrResourceLimit, length, offset, zeroWidthLimit)
		}

		fragment, err := codec.read(bb, length)
		if err != nil {
			return err
		}
		_, err = result.WriteString(fragment)
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return result.String(), total, nil
}
