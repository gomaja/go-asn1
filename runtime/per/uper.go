package per

import (
	"fmt"
	"math/bits"
)

// BitWidth returns the number of bits needed to represent values 0..rangeVal.
func BitWidth(rangeVal int64) int {
	if rangeVal <= 0 {
		return 0
	}
	return bits.Len64(uint64(rangeVal))
}

// EncodeBoolean encodes a boolean as 1 bit.
func EncodeBoolean(bb *BitBuffer, v bool) error {
	if v {
		return bb.WriteBit(1)
	}
	return bb.WriteBit(0)
}

// DecodeBoolean decodes a boolean from 1 bit.
func DecodeBoolean(bb *BitBuffer) (bool, error) {
	bit, err := bb.ReadBit()
	if err != nil {
		return false, err
	}
	return bit != 0, nil
}

// EncodeConstrainedWholeNumber encodes v in [lb..ub] using minimal bits.
// X.691 Section 12.2.2.
func EncodeConstrainedWholeNumber(bb *BitBuffer, v, lb, ub int64) error {
	rangeVal := ub - lb
	if rangeVal < 0 {
		return fmt.Errorf("%w: invalid range [%d..%d]", ErrInvalidValue, lb, ub)
	}
	if v < lb || v > ub {
		return fmt.Errorf("%w: %d not in [%d..%d]", ErrConstraintViolation, v, lb, ub)
	}
	if rangeVal == 0 {
		return nil // no bits needed
	}
	offset := v - lb
	n := BitWidth(rangeVal)
	return bb.WriteBits(uint64(offset), n)
}

// DecodeConstrainedWholeNumber decodes a value from [lb..ub].
func DecodeConstrainedWholeNumber(bb *BitBuffer, lb, ub int64) (int64, error) {
	rangeVal := ub - lb
	if rangeVal < 0 {
		return 0, fmt.Errorf("%w: invalid range [%d..%d]", ErrInvalidValue, lb, ub)
	}
	if rangeVal == 0 {
		return lb, nil
	}
	n := BitWidth(rangeVal)
	offset, err := bb.ReadBits(n)
	if err != nil {
		return 0, err
	}
	return lb + int64(offset), nil
}

// EncodeNormallySmallNonNegative encodes a normally small non-negative whole number.
// X.691 Section 11.6. Used for CHOICE extension index, bitmap lengths.
func EncodeNormallySmallNonNegative(bb *BitBuffer, v int64) error {
	if v < 0 {
		return fmt.Errorf("%w: negative value %d", ErrInvalidValue, v)
	}
	if v < 64 {
		if err := bb.WriteBit(0); err != nil {
			return err
		}
		return bb.WriteBits(uint64(v), 6)
	}
	if err := bb.WriteBit(1); err != nil {
		return err
	}
	return EncodeSemiConstrainedWholeNumber(bb, v, 0)
}

// DecodeNormallySmallNonNegative decodes a normally small non-negative whole number.
func DecodeNormallySmallNonNegative(bb *BitBuffer) (int64, error) {
	bit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		val, err := bb.ReadBits(6)
		if err != nil {
			return 0, err
		}
		return int64(val), nil
	}
	return DecodeSemiConstrainedWholeNumber(bb, 0)
}

// EncodeSemiConstrainedWholeNumber encodes v with known lower bound but no upper bound.
// X.691 Section 12.2.3.
func EncodeSemiConstrainedWholeNumber(bb *BitBuffer, v, lb int64) error {
	offset := v - lb
	if offset < 0 {
		return fmt.Errorf("%w: %d below lower bound %d", ErrConstraintViolation, v, lb)
	}
	return encodeNonNegativeBinaryIntegerWithLength(bb, uint64(offset))
}

// DecodeSemiConstrainedWholeNumber decodes a semi-constrained whole number.
func DecodeSemiConstrainedWholeNumber(bb *BitBuffer, lb int64) (int64, error) {
	offset, err := decodeNonNegativeBinaryIntegerWithLength(bb)
	if err != nil {
		return 0, err
	}
	return lb + int64(offset), nil
}

// EncodeUnconstrainedWholeNumber encodes a signed integer with no bounds.
// X.691 Section 12.2.4.
func EncodeUnconstrainedWholeNumber(bb *BitBuffer, v int64) error {
	// Encode as 2's complement with length determinant.
	var buf []byte
	if v >= 0 {
		if v == 0 {
			buf = []byte{0}
		} else {
			buf = minimalUnsignedBytes(uint64(v))
			// If high bit set, prepend a 0x00 byte for sign.
			if buf[0]&0x80 != 0 {
				buf = append([]byte{0}, buf...)
			}
		}
	} else {
		buf = minimalSignedNegBytes(v)
	}
	if err := EncodeUnconstrainedLength(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

// DecodeUnconstrainedWholeNumber decodes an unconstrained signed integer.
func DecodeUnconstrainedWholeNumber(bb *BitBuffer) (int64, error) {
	length, err := DecodeUnconstrainedLength(bb)
	if err != nil {
		return 0, err
	}
	if length == 0 {
		return 0, nil
	}
	data, err := bb.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}
	return twosComplementToInt64(data), nil
}

// EncodeUnconstrainedLength encodes a length determinant with no constraints.
// X.691 Section 11.9.
func EncodeUnconstrainedLength(bb *BitBuffer, n int64) error {
	if n < 0 {
		return fmt.Errorf("%w: negative length %d", ErrInvalidValue, n)
	}
	if n < 128 {
		// Short form: 0xxxxxxx
		return bb.WriteBits(uint64(n), 8)
	}
	if n < 16384 {
		// Long form: 10xxxxxx xxxxxxxx
		return bb.WriteBits(0x8000|uint64(n), 16)
	}
	// Fragmentation: not commonly needed, return error for now.
	return fmt.Errorf("per: length %d requires fragmentation (not yet supported)", n)
}

// DecodeUnconstrainedLength decodes an unconstrained length determinant.
func DecodeUnconstrainedLength(bb *BitBuffer) (int64, error) {
	firstBit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if firstBit == 0 {
		// Short form: remaining 7 bits.
		val, err := bb.ReadBits(7)
		if err != nil {
			return 0, err
		}
		return int64(val), nil
	}
	secondBit, err := bb.ReadBit()
	if err != nil {
		return 0, err
	}
	if secondBit == 0 {
		// Long form: remaining 14 bits.
		val, err := bb.ReadBits(14)
		if err != nil {
			return 0, err
		}
		return int64(val), nil
	}
	// Fragmentation marker (11xxxxxx).
	// Read remaining 6 bits to see the multiplier
	mul, err := bb.ReadBits(6)
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("per: fragmented length determinant not yet supported (mul=%d, bitPos=%d)", mul, bb.BitPos())
}

// EncodeInteger encodes an integer using the appropriate method based on constraints.
func EncodeInteger(bb *BitBuffer, v int64, lb, ub *int64, extensible bool) error {
	if extensible {
		inRoot := true
		if lb != nil && v < *lb {
			inRoot = false
		}
		if ub != nil && v > *ub {
			inRoot = false
		}
		if err := EncodeBoolean(bb, !inRoot); err != nil {
			return err
		}
		if !inRoot {
			return EncodeUnconstrainedWholeNumber(bb, v)
		}
	}
	if lb != nil && ub != nil {
		return EncodeConstrainedWholeNumber(bb, v, *lb, *ub)
	}
	if lb != nil {
		return EncodeSemiConstrainedWholeNumber(bb, v, *lb)
	}
	return EncodeUnconstrainedWholeNumber(bb, v)
}

// DecodeInteger decodes an integer using the appropriate method based on constraints.
func DecodeInteger(bb *BitBuffer, lb, ub *int64, extensible bool) (int64, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			return DecodeUnconstrainedWholeNumber(bb)
		}
	}
	if lb != nil && ub != nil {
		return DecodeConstrainedWholeNumber(bb, *lb, *ub)
	}
	if lb != nil {
		return DecodeSemiConstrainedWholeNumber(bb, *lb)
	}
	return DecodeUnconstrainedWholeNumber(bb)
}

// EncodeEnumerated encodes an enumerated value.
// rootCount = number of root enumeration values, extensible = has "..." marker.
func EncodeEnumerated(bb *BitBuffer, v int64, rootCount int, extensible bool) error {
	if extensible {
		isExtension := v >= int64(rootCount)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			return EncodeNormallySmallNonNegative(bb, v-int64(rootCount))
		}
	}
	if rootCount <= 1 {
		return nil // single value, no bits needed
	}
	return EncodeConstrainedWholeNumber(bb, v, 0, int64(rootCount-1))
}

// DecodeEnumerated decodes an enumerated value.
func DecodeEnumerated(bb *BitBuffer, rootCount int, extensible bool) (int64, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, err
		}
		if isExtension {
			extIdx, err := DecodeNormallySmallNonNegative(bb)
			if err != nil {
				return 0, err
			}
			return int64(rootCount) + extIdx, nil
		}
	}
	if rootCount <= 1 {
		return 0, nil
	}
	return DecodeConstrainedWholeNumber(bb, 0, int64(rootCount-1))
}

// EncodeBitString encodes a bit string.
// If constrained and lb == ub: fixed size, no length.
// If constrained and ub <= 65536: constrained length + bits.
// Otherwise: unconstrained length + bits.
func EncodeBitString(bb *BitBuffer, data []byte, bitLen int, lb, ub int64, constrained bool) error {
	if constrained && lb == ub {
		// Fixed size — write exactly lb bits.
		return bb.WriteBitsFromBytes(data, int(lb))
	}
	if constrained && ub <= 65536 {
		if err := EncodeConstrainedWholeNumber(bb, int64(bitLen), lb, ub); err != nil {
			return err
		}
		return bb.WriteBitsFromBytes(data, bitLen)
	}
	// Unconstrained.
	if err := EncodeUnconstrainedLength(bb, int64(bitLen)); err != nil {
		return err
	}
	return bb.WriteBitsFromBytes(data, bitLen)
}

// DecodeBitString decodes a bit string. Returns (bytes, bitLength, error).
func DecodeBitString(bb *BitBuffer, lb, ub int64, constrained bool) ([]byte, int, error) {
	if constrained && lb == ub {
		data, err := bb.ReadBitsToBytes(int(lb))
		return data, int(lb), err
	}
	var bitLen int64
	var err error
	if constrained && ub <= 65536 {
		bitLen, err = DecodeConstrainedWholeNumber(bb, lb, ub)
	} else {
		bitLen, err = DecodeUnconstrainedLength(bb)
	}
	if err != nil {
		return nil, 0, err
	}
	data, err := bb.ReadBitsToBytes(int(bitLen))
	return data, int(bitLen), err
}

// EncodeOctetString encodes an octet string.
// If constrained and lb == ub: fixed size, no length.
// If constrained and ub <= 65536: constrained length + octets.
// Otherwise: unconstrained length + octets.
func EncodeOctetString(bb *BitBuffer, data []byte, lb, ub int64, constrained bool) error {
	length := int64(len(data))
	if constrained && lb == ub {
		// Fixed size — write exactly lb octets.
		return bb.WriteBytes(data)
	}
	if constrained && ub <= 65536 {
		if err := EncodeConstrainedWholeNumber(bb, length, lb, ub); err != nil {
			return err
		}
		return bb.WriteBytes(data)
	}
	// Unconstrained.
	if err := EncodeUnconstrainedLength(bb, length); err != nil {
		return err
	}
	return bb.WriteBytes(data)
}

// DecodeOctetString decodes an octet string.
func DecodeOctetString(bb *BitBuffer, lb, ub int64, constrained bool) ([]byte, error) {
	if constrained && lb == ub {
		return bb.ReadBytes(int(lb))
	}
	var length int64
	var err error
	if constrained && ub <= 65536 {
		length, err = DecodeConstrainedWholeNumber(bb, lb, ub)
	} else {
		length, err = DecodeUnconstrainedLength(bb)
	}
	if err != nil {
		return nil, err
	}
	return bb.ReadBytes(int(length))
}

// EncodeNull is a no-op (NULL = 0 bits in UPER).
func EncodeNull(_ *BitBuffer) error {
	return nil
}

// DecodeNull is a no-op.
func DecodeNull(_ *BitBuffer) error {
	return nil
}

// EncodeKnownMultiplierString encodes a string with known character set.
// bitsPerChar is the bits per character (e.g., 7 for IA5String/VisibleString, 4 for NumericString).
func EncodeKnownMultiplierString(bb *BitBuffer, s string, bitsPerChar int, lb, ub int64, constrained bool) error {
	length := int64(len(s))
	if constrained && lb == ub {
		// Fixed size — write exactly lb characters.
		for _, ch := range []byte(s) {
			if err := bb.WriteBits(uint64(ch), bitsPerChar); err != nil {
				return err
			}
		}
		return nil
	}
	if constrained && ub <= 65536 {
		if err := EncodeConstrainedWholeNumber(bb, length, lb, ub); err != nil {
			return err
		}
	} else {
		if err := EncodeUnconstrainedLength(bb, length); err != nil {
			return err
		}
	}
	for _, ch := range []byte(s) {
		if err := bb.WriteBits(uint64(ch), bitsPerChar); err != nil {
			return err
		}
	}
	return nil
}

// DecodeKnownMultiplierString decodes a string with known character set.
func DecodeKnownMultiplierString(bb *BitBuffer, bitsPerChar int, lb, ub int64, constrained bool) (string, error) {
	var length int64
	var err error
	if constrained && lb == ub {
		length = lb
	} else if constrained && ub <= 65536 {
		length, err = DecodeConstrainedWholeNumber(bb, lb, ub)
		if err != nil {
			return "", err
		}
	} else {
		length, err = DecodeUnconstrainedLength(bb)
		if err != nil {
			return "", err
		}
	}
	buf := make([]byte, length)
	for i := int64(0); i < length; i++ {
		val, err := bb.ReadBits(bitsPerChar)
		if err != nil {
			return "", err
		}
		buf[i] = byte(val)
	}
	return string(buf), nil
}

// EncodeOpenType wraps already-encoded bytes with an unconstrained length determinant.
// Used for extension additions and open type fields.
func EncodeOpenType(bb *BitBuffer, data []byte) error {
	if err := EncodeUnconstrainedLength(bb, int64(len(data))); err != nil {
		return err
	}
	return bb.WriteBytes(data)
}

// DecodeOpenType decodes an open type value.
func DecodeOpenType(bb *BitBuffer) ([]byte, error) {
	length, err := DecodeUnconstrainedLength(bb)
	if err != nil {
		return nil, err
	}
	return bb.ReadBytes(int(length))
}

// EncodeLength encodes a length determinant for SEQUENCE_OF/SET_OF.
// If constrained is false, uses unconstrained length determinant (X.691 Section 11.9).
// This is an alias provided for clarity in generated code.
func EncodeLength(bb *BitBuffer, n int64, constrained bool) error {
	if constrained {
		return fmt.Errorf("per: constrained length encoding should use EncodeConstrainedWholeNumber")
	}
	return EncodeUnconstrainedLength(bb, n)
}

// DecodeLength decodes a length determinant for SEQUENCE_OF/SET_OF.
// If constrained is false, uses unconstrained length determinant.
func DecodeLength(bb *BitBuffer, constrained bool) (int64, error) {
	if constrained {
		return 0, fmt.Errorf("per: constrained length decoding should use DecodeConstrainedWholeNumber")
	}
	return DecodeUnconstrainedLength(bb)
}

// EncodeChoiceIndex encodes a CHOICE index for root alternatives.
func EncodeChoiceIndex(bb *BitBuffer, index int64, numAlternatives int, extensible bool) error {
	if extensible {
		isExtension := index >= int64(numAlternatives)
		if err := EncodeBoolean(bb, isExtension); err != nil {
			return err
		}
		if isExtension {
			return EncodeNormallySmallNonNegative(bb, index-int64(numAlternatives))
		}
	}
	if numAlternatives <= 1 {
		return nil
	}
	return EncodeConstrainedWholeNumber(bb, index, 0, int64(numAlternatives-1))
}

// DecodeChoiceIndex decodes a CHOICE index.
func DecodeChoiceIndex(bb *BitBuffer, numAlternatives int, extensible bool) (int64, bool, error) {
	if extensible {
		isExtension, err := DecodeBoolean(bb)
		if err != nil {
			return 0, false, err
		}
		if isExtension {
			idx, err := DecodeNormallySmallNonNegative(bb)
			if err != nil {
				return 0, true, err
			}
			return int64(numAlternatives) + idx, true, nil
		}
	}
	if numAlternatives <= 1 {
		return 0, false, nil
	}
	idx, err := DecodeConstrainedWholeNumber(bb, 0, int64(numAlternatives-1))
	return idx, false, err
}

// --- internal helpers ---

func encodeNonNegativeBinaryIntegerWithLength(bb *BitBuffer, v uint64) error {
	buf := minimalUnsignedBytes(v)
	if err := EncodeUnconstrainedLength(bb, int64(len(buf))); err != nil {
		return err
	}
	return bb.WriteBytes(buf)
}

func decodeNonNegativeBinaryIntegerWithLength(bb *BitBuffer) (uint64, error) {
	length, err := DecodeUnconstrainedLength(bb)
	if err != nil {
		return 0, err
	}
	if length == 0 {
		return 0, nil
	}
	data, err := bb.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}
	var val uint64
	for _, b := range data {
		val = (val << 8) | uint64(b)
	}
	return val, nil
}

func minimalUnsignedBytes(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	n := (bits.Len64(v) + 7) / 8
	buf := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte(v)
		v >>= 8
	}
	return buf
}

func minimalSignedNegBytes(v int64) []byte {
	// Encode negative v as minimal 2's complement.
	uv := uint64(v)
	// Find minimal byte count: start from 1 and check sign extension.
	for n := 1; n <= 8; n++ {
		// Check if n bytes can represent v.
		shift := uint(n * 8)
		if n == 8 || (int64(uv<<(64-shift))>>(64-shift)) == v {
			buf := make([]byte, n)
			for i := n - 1; i >= 0; i-- {
				buf[i] = byte(uv)
				uv >>= 8
			}
			return buf
		}
	}
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(uv)
		uv >>= 8
	}
	return buf
}

func twosComplementToInt64(data []byte) int64 {
	if len(data) == 0 {
		return 0
	}
	// Sign extend.
	var val int64
	if data[0]&0x80 != 0 {
		val = -1
	}
	for _, b := range data {
		val = (val << 8) | int64(b)
	}
	return val
}
