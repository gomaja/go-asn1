package per

import (
	"fmt"
	"math"
	"math/bits"
	"strings"
	"unicode/utf8"
)

// PermittedAlphabet is the effective permitted alphabet of a known-multiplier
// character string type, ITU-T X.691 (02/2021) 30.5.1. It lists the character
// values of X.691 30.5.3 as inclusive {first, last} pairs in ascending order;
// pairs neither overlap nor touch. The values are the ISO/IEC 646 codes for
// NumericString, PrintableString, VisibleString and IA5String, and the
// ISO/IEC 10646 cell values for BMPString and UniversalString.
type PermittedAlphabet []uint32

// NumericStringAlphabet is the NumericString character set, space and the ten
// digits (ITU-T X.680 (02/2021) 41.2, Table 9). X.691 (02/2021) 30.5.4 b)
// always applies to it, so its characters encode as indexes in 4 bits.
var NumericStringAlphabet = PermittedAlphabet{' ', ' ', '0', '9'}

// EncodeAlphabetString encodes a known-multiplier character string whose
// characters are limited to alphabet (UNALIGNED variant, ITU-T X.691 (02/2021)
// 30.4 and 30.5). Characters outside alphabet are rejected before anything is
// written.
func EncodeAlphabetString(bb *BitBuffer, s string, alphabet PermittedAlphabet, lb, ub int64, constrained, extensible bool) error {
	codec, err := alphabet.characterCodec(false)
	if err != nil {
		return err
	}
	return encodeCharacterString(bb, s, codec, lb, ub, constrained, extensible, false)
}

// DecodeAlphabetString decodes a string encoded by EncodeAlphabetString.
// A character value outside alphabet is rejected.
func DecodeAlphabetString(bb *BitBuffer, alphabet PermittedAlphabet, lb, ub int64, constrained, extensible bool) (string, error) {
	codec, err := alphabet.characterCodec(false)
	if err != nil {
		return "", err
	}
	return decodeCharacterString(bb, codec, lb, ub, constrained, extensible, false)
}

// EncodeAlphabetStringAligned is EncodeAlphabetString in the ALIGNED variant.
func EncodeAlphabetStringAligned(bb *BitBuffer, s string, alphabet PermittedAlphabet, lb, ub int64, constrained, extensible bool) error {
	codec, err := alphabet.characterCodec(true)
	if err != nil {
		return err
	}
	return encodeCharacterString(bb, s, codec, lb, ub, constrained, extensible, true)
}

// DecodeAlphabetStringAligned is DecodeAlphabetString in the ALIGNED variant.
func DecodeAlphabetStringAligned(bb *BitBuffer, alphabet PermittedAlphabet, lb, ub int64, constrained, extensible bool) (string, error) {
	codec, err := alphabet.characterCodec(true)
	if err != nil {
		return "", err
	}
	return decodeCharacterString(bb, codec, lb, ub, constrained, extensible, true)
}

// characterCodec is the character encoding of ITU-T X.691 (02/2021) 30.5.2
// to 30.5.5 for one variant.
type characterCodec struct {
	// bits is "b": B in the UNALIGNED variant and B2 in the ALIGNED one
	// (30.5.2).
	bits int
	// valueBits bounds the character values when alphabet is nil: every
	// value below 2 to the power valueBits is a character.
	valueBits int
	// alphabet, when set, lists the only permitted characters.
	alphabet PermittedAlphabet
	// indexed selects 30.5.4 b): a character encodes as its position in the
	// canonical order of the alphabet rather than as its own value.
	indexed bool
	// wide marks strings held as UTF-8 runes; otherwise each octet of the Go
	// string is one character.
	wide bool
}

// identityCharacterCodec covers a type's whole alphabet when all its values
// fit in alphabetBits, which is B of 30.5.2; 30.5.4 a) then applies in both
// variants, because B2 is at least B.
func identityCharacterCodec(alphabetBits int, aligned bool) (characterCodec, error) {
	if err := validateKnownMultiplierWidth(alphabetBits); err != nil {
		return characterCodec{}, err
	}
	width := alphabetBits
	if aligned {
		width = alignedCharacterBits(alphabetBits)
	}
	return characterCodec{bits: width, valueBits: alphabetBits, wide: alphabetBits > 8}, nil
}

// alignedCharacterBits returns B2, the smallest power of two that is greater
// than or equal to B (ITU-T X.691 (02/2021) 30.5.2).
func alignedCharacterBits(alphabetBits int) int {
	width := 1
	for width < alphabetBits {
		width <<= 1
	}
	return width
}

func validateKnownMultiplierWidth(bitsPerChar int) error {
	if bitsPerChar < 1 || bitsPerChar > 32 {
		return fmt.Errorf("%w: character width %d bits is outside [1..32]", ErrInvalidValue, bitsPerChar)
	}
	return nil
}

// characterCodec derives b and the value mapping of ITU-T X.691 (02/2021)
// 30.5.2 and 30.5.4 from the alphabet.
func (alphabet PermittedAlphabet) characterCodec(aligned bool) (characterCodec, error) {
	count, err := alphabet.size()
	if err != nil {
		return characterCodec{}, err
	}
	// B is the smallest integer with 2^B >= N, so a one-character alphabet
	// has B = 0: its UNALIGNED characters take no bits, and B2, the smallest
	// power of two not below B, is 1.
	alphabetBits := bits.Len64(count - 1)
	width := alphabetBits
	if aligned {
		width = alignedCharacterBits(alphabetBits)
	}
	largest := alphabet[len(alphabet)-1]
	return characterCodec{
		bits:     width,
		alphabet: alphabet,
		indexed:  uint64(largest) > uint64(1)<<width-1,
		wide:     largest > utf8.RuneSelf-1,
	}, nil
}

// size validates the alphabet and returns its character count N.
func (alphabet PermittedAlphabet) size() (uint64, error) {
	if len(alphabet) == 0 || len(alphabet)%2 != 0 {
		return 0, fmt.Errorf("%w: permitted alphabet needs non-empty {first, last} pairs, has %d values", ErrInvalidValue, len(alphabet))
	}
	var count uint64
	for index := 0; index < len(alphabet); index += 2 {
		first, last := alphabet[index], alphabet[index+1]
		if first > last {
			return 0, fmt.Errorf("%w: permitted alphabet range %#x..%#x is reversed", ErrInvalidValue, first, last)
		}
		if index > 0 && uint64(first) <= uint64(alphabet[index-1])+1 {
			return 0, fmt.Errorf("%w: permitted alphabet range starting %#x overlaps or touches the previous range", ErrInvalidValue, first)
		}
		count += uint64(last-first) + 1
	}
	return count, nil
}

// encodeValue maps a character value to the bits written for it.
func (codec characterCodec) encodeValue(value uint32) (uint64, error) {
	if codec.alphabet == nil {
		if uint64(value) >= uint64(1)<<codec.valueBits {
			return 0, fmt.Errorf("%w: character %#x does not fit in %d bits", ErrConstraintViolation, value, codec.valueBits)
		}
		return uint64(value), nil
	}
	var position uint64
	for index := 0; index < len(codec.alphabet); index += 2 {
		first, last := codec.alphabet[index], codec.alphabet[index+1]
		if value < first {
			break
		}
		if value <= last {
			if codec.indexed {
				return position + uint64(value-first), nil
			}
			return uint64(value), nil
		}
		position += uint64(last-first) + 1
	}
	return 0, fmt.Errorf("%w: character %#x is not in the permitted alphabet", ErrConstraintViolation, value)
}

// decodeValue maps the bits read for a character to its value.
func (codec characterCodec) decodeValue(code uint64) (uint32, error) {
	if codec.alphabet == nil {
		if code >= uint64(1)<<codec.valueBits {
			return 0, fmt.Errorf("%w: character %#x does not fit in %d bits", ErrInvalidValue, code, codec.valueBits)
		}
		return uint32(code), nil
	}
	var position uint64
	for index := 0; index < len(codec.alphabet); index += 2 {
		first, last := codec.alphabet[index], codec.alphabet[index+1]
		width := uint64(last-first) + 1
		if codec.indexed {
			if code < position+width {
				return first + uint32(code-position), nil
			}
		} else if code >= uint64(first) && code <= uint64(last) {
			return uint32(code), nil
		}
		position += width
	}
	return 0, fmt.Errorf("%w: character %#x is not in the permitted alphabet", ErrInvalidValue, code)
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

// alignsVariable reports whether the ALIGNED variant octet-aligns the
// characters of a constrained length: 30.5.7 aligns when "aub" times "b" is
// 16 or more.
func (codec characterCodec) alignsVariable(ub int64) (bool, error) {
	payloadBits, err := codec.payloadBits(ub)
	return payloadBits >= 16, err
}

// alignsFixed reports whether the ALIGNED variant octet-aligns a fixed-size
// string: 30.5.6 aligns when "aub" times "b" is greater than 16.
func (codec characterCodec) alignsFixed(size int64) (bool, error) {
	payloadBits, err := codec.payloadBits(size)
	return payloadBits > 16, err
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
			return encodeLengthDelimitedCharacters(bb, value, length, codec, aligned)
		}
	}
	if err := validateRootSize(length, lb, ub, constrained); err != nil {
		return err
	}
	if fixedRootSizeOmitsLength(lb, ub, constrained) {
		if aligned {
			align, err := codec.alignsFixed(lb)
			if err != nil {
				return err
			}
			if align {
				if err := bb.AlignToOctetWrite(); err != nil {
					return err
				}
			}
		}
		return codec.write(bb, value)
	}
	if !constrained || ub >= 65536 {
		return encodeLengthDelimitedCharacters(bb, value, length, codec, aligned)
	}
	if aligned {
		err = EncodeConstrainedWholeNumberAligned(bb, length, lb, ub)
	} else {
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
	if aligned {
		align, err := codec.alignsVariable(ub)
		if err != nil {
			return err
		}
		if align {
			if err := bb.AlignToOctetWrite(); err != nil {
				return err
			}
		}
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
			value, decodedLength, err := decodeLengthDelimitedCharacters(bb, codec, aligned, math.MaxInt64)
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
		if aligned {
			align, err := codec.alignsFixed(lb)
			if err != nil {
				return "", err
			}
			if align {
				if err := bb.AlignToOctetRead(); err != nil {
					return "", err
				}
			}
		}
		return codec.read(bb, lb)
	}
	if !constrained || ub >= 65536 {
		value, decodedLength, err := decodeLengthDelimitedCharacters(bb, codec, aligned, rootSizeMaximum(ub, constrained))
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
	if aligned {
		length, err = DecodeConstrainedWholeNumberAligned(bb, lb, ub)
	} else {
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
	if aligned {
		align, err := codec.alignsVariable(ub)
		if err != nil {
			return "", err
		}
		if align {
			if err := bb.AlignToOctetRead(); err != nil {
				return "", err
			}
		}
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
	return EncodeLengthFragments(bb, length, aligned, func(offset, fragmentLength int64) error {
		if aligned {
			if err := bb.AlignToOctetWrite(); err != nil {
				return err
			}
		}
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
	total, err := decodeLengthFragmentsBounded(bb, aligned, maximum, func(offset int64, length int64) error {
		// Zero-bit characters consume no input, so only this operational
		// limit bounds a decoded length that X.691 (02/2021) 11.9 leaves
		// unbounded. Schema-bounded lengths below 64K never reach it.
		if codec.bits == 0 && length > zeroWidthLimit-offset {
			return fmt.Errorf("%w: %d zero-bit characters after %d exceed the limit of %d", ErrResourceLimit, length, offset, zeroWidthLimit)
		}
		if aligned {
			if err := bb.AlignToOctetRead(); err != nil {
				return err
			}
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
