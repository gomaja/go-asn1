package ber

import (
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// DecodeTag reads an ASN.1 tag from data and returns the tag plus bytes consumed.
func DecodeTag(data []byte) (tag.Tag, int, error) {
	if len(data) == 0 {
		return tag.Tag{}, 0, ErrTruncated
	}

	b := data[0]
	t := tag.Tag{
		Class:       tag.Class(b >> 6),
		Constructed: b&0x20 != 0,
	}

	tagNum := int(b & 0x1F)
	if tagNum < 31 {
		t.Number = tagNum
		return t, 1, nil
	}

	// Long form tag number.
	offset := 1
	t.Number = 0
	for {
		if offset >= len(data) {
			return tag.Tag{}, 0, ErrTruncated
		}
		b = data[offset]
		offset++
		t.Number = (t.Number << 7) | int(b&0x7F)
		if b&0x80 == 0 {
			break
		}
	}
	return t, offset, nil
}

// DecodeLength reads a BER length field from data and returns the length,
// whether it's indefinite, and bytes consumed.
func DecodeLength(data []byte) (length int, indefinite bool, consumed int, err error) {
	if len(data) == 0 {
		return 0, false, 0, ErrTruncated
	}

	b := data[0]
	if b < 128 {
		return int(b), false, 1, nil
	}
	if b == 0x80 {
		return 0, true, 1, nil
	}

	numBytes := int(b & 0x7F)
	if numBytes > 4 || numBytes == 0 {
		return 0, false, 0, fmt.Errorf("%w: length field too large (%d bytes)", ErrInvalidLength, numBytes)
	}
	if 1+numBytes > len(data) {
		return 0, false, 0, ErrTruncated
	}

	length = 0
	for i := 1; i <= numBytes; i++ {
		length = (length << 8) | int(data[i])
	}
	return length, false, 1 + numBytes, nil
}

// DecodeTLV reads one complete TLV element from data.
// Returns the tag, bytes consumed, and the value bytes.
func DecodeTLV(data []byte) (tag.Tag, int, []byte, error) {
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}

	length, indefinite, lenLen, err := DecodeLength(data[tagLen:])
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}

	headerLen := tagLen + lenLen

	if indefinite {
		// Scan for end-of-contents octets (0x00, 0x00).
		pos := headerLen
		depth := 0
		for {
			if pos+2 > len(data) {
				return tag.Tag{}, 0, nil, ErrTruncated
			}
			if data[pos] == 0x00 && data[pos+1] == 0x00 {
				if depth == 0 {
					value := data[headerLen:pos]
					return t, pos + 2, value, nil
				}
				depth--
				pos += 2
				continue
			}
			// Skip nested TLVs.
			_, innerTagLen, err := DecodeTag(data[pos:])
			if err != nil {
				return tag.Tag{}, 0, nil, err
			}
			innerLen, innerIndef, innerLenLen, err := DecodeLength(data[pos+innerTagLen:])
			if err != nil {
				return tag.Tag{}, 0, nil, err
			}
			if innerIndef {
				depth++
				pos += innerTagLen + innerLenLen
			} else {
				pos += innerTagLen + innerLenLen + innerLen
			}
		}
	}

	end := headerLen + length
	if end > len(data) {
		return tag.Tag{}, 0, nil, ErrTruncated
	}

	return t, end, data[headerLen:end], nil
}

// DecodeSequenceChildren splits the value bytes of a constructed TLV into child TLVs.
// Returns a slice of raw child TLV byte slices.
func DecodeSequenceChildren(data []byte) ([][]byte, error) {
	var children [][]byte
	offset := 0
	for offset < len(data) {
		t, total, value, err := DecodeTLV(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("at offset %d: %w", offset, err)
		}
		_ = t
		_ = value
		children = append(children, data[offset:offset+total])
		offset += total
	}
	return children, nil
}

// DecodeBoolean decodes a boolean from raw TLV bytes.
// Returns (value, rawByte, totalConsumed, error).
func DecodeBoolean(data []byte) (bool, byte, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return false, 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagBoolean {
		return false, 0, 0, fmt.Errorf("%w: expected BOOLEAN tag, got %s", ErrInvalidTag, t)
	}
	if len(value) != 1 {
		return false, 0, 0, fmt.Errorf("%w: BOOLEAN value must be 1 byte, got %d", ErrInvalidValue, len(value))
	}
	return value[0] != 0, value[0], total, nil
}

// DecodeInteger decodes an integer from raw TLV bytes.
func DecodeInteger(data []byte) (int64, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || (t.Number != tag.TagInteger && t.Number != tag.TagEnumerated) {
		return 0, 0, fmt.Errorf("%w: expected INTEGER/ENUMERATED tag, got %s", ErrInvalidTag, t)
	}
	if len(value) == 0 {
		return 0, 0, fmt.Errorf("%w: INTEGER value must have at least 1 byte", ErrInvalidValue)
	}
	v, err := decodeIntBytes(value)
	if err != nil {
		return 0, 0, err
	}
	return v, total, nil
}

func decodeIntBytes(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("%w: empty integer", ErrInvalidValue)
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("%w: integer too large for int64 (%d bytes)", ErrInvalidValue, len(b))
	}

	var v int64
	// Sign-extend the first byte.
	if b[0]&0x80 != 0 {
		v = -1 // All 1s.
	}
	for _, c := range b {
		v = (v << 8) | int64(c)
	}
	return v, nil
}

// DecodeBigInt decodes an integer from raw TLV bytes into a *big.Int.
func DecodeBigInt(data []byte) (*big.Int, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagInteger {
		return nil, 0, fmt.Errorf("%w: expected INTEGER tag, got %s", ErrInvalidTag, t)
	}
	if len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: INTEGER value must have at least 1 byte", ErrInvalidValue)
	}

	v := new(big.Int)
	if value[0]&0x80 != 0 {
		// Negative: convert two's complement.
		notBytes := make([]byte, len(value))
		for i, b := range value {
			notBytes[i] = ^b
		}
		v.SetBytes(notBytes)
		v.Add(v, big.NewInt(1))
		v.Neg(v)
	} else {
		v.SetBytes(value)
	}
	return v, total, nil
}

// DecodeBitString decodes a bit string from raw TLV bytes.
// Returns the bytes, unused bits count, and total bytes consumed.
func DecodeBitString(data []byte) ([]byte, int, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return nil, 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagBitString {
		return nil, 0, 0, fmt.Errorf("%w: expected BIT STRING tag, got %s", ErrInvalidTag, t)
	}
	if len(value) == 0 {
		return nil, 0, total, nil // Empty bit string.
	}
	unusedBits := int(value[0])
	if unusedBits > 7 {
		return nil, 0, 0, fmt.Errorf("%w: invalid unused bits count %d", ErrInvalidValue, unusedBits)
	}
	return value[1:], unusedBits, total, nil
}

// DecodeOctetString decodes an octet string from raw TLV bytes.
func DecodeOctetString(data []byte) ([]byte, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagOctetString {
		return nil, 0, fmt.Errorf("%w: expected OCTET STRING tag, got %s", ErrInvalidTag, t)
	}
	// Handle constructed form (BER allows it).
	if t.Constructed {
		var result []byte
		children, err := DecodeSequenceChildren(value)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding constructed OCTET STRING: %w", err)
		}
		for _, child := range children {
			childVal, _, err := DecodeOctetString(child)
			if err != nil {
				return nil, 0, err
			}
			result = append(result, childVal...)
		}
		return result, total, nil
	}
	return value, total, nil
}

// DecodeNull decodes a NULL from raw TLV bytes.
func DecodeNull(data []byte) (int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagNull {
		return 0, fmt.Errorf("%w: expected NULL tag, got %s", ErrInvalidTag, t)
	}
	if len(value) != 0 {
		return 0, fmt.Errorf("%w: NULL value must be empty, got %d bytes", ErrInvalidValue, len(value))
	}
	return total, nil
}

// DecodeObjectIdentifier decodes an OID from raw TLV bytes.
func DecodeObjectIdentifier(data []byte) ([]uint64, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagObjectID {
		return nil, 0, fmt.Errorf("%w: expected OBJECT IDENTIFIER tag, got %s", ErrInvalidTag, t)
	}
	if len(value) == 0 {
		return nil, total, nil
	}

	// Decode first two components.
	firstVal, offset := decodeBase128(value, 0)
	var oid []uint64
	if firstVal < 80 {
		oid = append(oid, firstVal/40, firstVal%40)
	} else {
		oid = append(oid, 2, firstVal-80)
	}

	// Decode remaining components.
	for offset < len(value) {
		v, newOffset := decodeBase128(value, offset)
		oid = append(oid, v)
		offset = newOffset
	}

	return oid, total, nil
}

func decodeBase128(data []byte, offset int) (uint64, int) {
	var v uint64
	for offset < len(data) {
		b := data[offset]
		offset++
		v = (v << 7) | uint64(b&0x7F)
		if b&0x80 == 0 {
			break
		}
	}
	return v, offset
}

// DecodeEnumerated decodes an ENUMERATED value from raw TLV bytes.
func DecodeEnumerated(data []byte) (int64, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagEnumerated {
		return 0, 0, fmt.Errorf("%w: expected ENUMERATED tag, got %s", ErrInvalidTag, t)
	}
	if len(value) == 0 {
		return 0, 0, fmt.Errorf("%w: ENUMERATED value must have at least 1 byte", ErrInvalidValue)
	}
	v, err := decodeIntBytes(value)
	if err != nil {
		return 0, 0, err
	}
	return v, total, nil
}

// DecodeReal decodes a REAL value from raw TLV bytes.
func DecodeReal(data []byte) (float64, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagReal {
		return 0, 0, fmt.Errorf("%w: expected REAL tag, got %s", ErrInvalidTag, t)
	}
	if len(value) == 0 {
		return 0, total, nil // Zero.
	}

	info := value[0]
	if info == 0x40 {
		return math.Inf(1), total, nil
	}
	if info == 0x41 {
		return math.Inf(-1), total, nil
	}
	if info == 0x42 {
		return math.NaN(), total, nil
	}

	if info&0x80 == 0 {
		return 0, 0, fmt.Errorf("%w: decimal/character REAL encoding not supported", ErrUnsupported)
	}

	// Binary encoding.
	sign := (info >> 6) & 1
	base := (info >> 4) & 3
	scaleFactor := (info >> 2) & 3
	expLen := int(info&3) + 1

	if base != 0 {
		return 0, 0, fmt.Errorf("%w: REAL base must be 2, got %d", ErrInvalidValue, base)
	}

	offset := 1
	if info&3 == 3 {
		if offset >= len(value) {
			return 0, 0, ErrTruncated
		}
		expLen = int(value[offset])
		offset++
	}

	if offset+expLen > len(value) {
		return 0, 0, ErrTruncated
	}

	// Decode exponent (signed).
	expBytes := value[offset : offset+expLen]
	exp, err := decodeIntBytes(expBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("decoding REAL exponent: %w", err)
	}
	offset += expLen

	// Decode mantissa (unsigned).
	mantBytes := value[offset:]
	if len(mantBytes) == 0 {
		return 0, 0, fmt.Errorf("%w: REAL mantissa empty", ErrInvalidValue)
	}
	var mantissa uint64
	for _, b := range mantBytes {
		mantissa = (mantissa << 8) | uint64(b)
	}

	// Result = (-1)^sign * mantissa * 2^scaleFactor * 2^exponent
	result := float64(mantissa) * math.Pow(2, float64(exp)+float64(scaleFactor))
	if sign == 1 {
		result = -result
	}
	return result, total, nil
}

// DecodeString decodes a string type (UTF8, IA5, PrintableString, etc.) from raw TLV bytes.
// The caller provides the expected tag number.
func DecodeString(data []byte, expectedTag int) (string, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return "", 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != expectedTag {
		return "", 0, fmt.Errorf("%w: expected tag %d, got %s", ErrInvalidTag, expectedTag, t)
	}
	return string(value), total, nil
}

// DecodeUTCTime decodes a UTCTime value.
func DecodeUTCTime(data []byte) (time.Time, int, error) {
	s, total, err := DecodeString(data, tag.TagUTCTime)
	if err != nil {
		return time.Time{}, 0, err
	}
	// Try common formats.
	for _, layout := range []string{
		"060102150405Z",
		"0601021504Z",
		"060102150405-0700",
		"060102150405+0700",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, total, nil
		}
	}
	return time.Time{}, 0, fmt.Errorf("%w: cannot parse UTCTime %q", ErrInvalidValue, s)
}

// DecodeGeneralizedTime decodes a GeneralizedTime value.
func DecodeGeneralizedTime(data []byte) (time.Time, int, error) {
	s, total, err := DecodeString(data, tag.TagGeneralizedTime)
	if err != nil {
		return time.Time{}, 0, err
	}
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405",
		"20060102150405.000Z",
		"20060102150405-0700",
		"20060102150405+0700",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, total, nil
		}
	}
	return time.Time{}, 0, fmt.Errorf("%w: cannot parse GeneralizedTime %q", ErrInvalidValue, s)
}

// DecodeRawValue reads one complete TLV without interpreting the value.
// Returns the full TLV bytes including tag and length.
func DecodeRawValue(data []byte) (tag.Tag, []byte, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return tag.Tag{}, nil, 0, err
	}
	return t, value, total, nil
}

// PeekTag reads the tag from data without consuming it.
func PeekTag(data []byte) (tag.Tag, error) {
	t, _, err := DecodeTag(data)
	return t, err
}

// --- Value-level decoders for generated code ---
// These decode from raw value bytes (tag+length already consumed).

// DecodeIntegerValue decodes an integer from raw value bytes.
func DecodeIntegerValue(value []byte) (int64, error) {
	return decodeIntBytes(value)
}

// DecodeBooleanValue decodes a boolean from raw value bytes.
func DecodeBooleanValue(value []byte) (bool, error) {
	if len(value) != 1 {
		return false, fmt.Errorf("%w: BOOLEAN value must be 1 byte, got %d", ErrInvalidValue, len(value))
	}
	return value[0] != 0, nil
}

// DecodeBitStringValue decodes a bit string from raw value bytes.
func DecodeBitStringValue(value []byte) ([]byte, int, error) {
	if len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: empty BIT STRING value", ErrInvalidValue)
	}
	unusedBits := int(value[0])
	if unusedBits > 7 {
		return nil, 0, fmt.Errorf("%w: BIT STRING unused bits %d out of range (0-7)", ErrInvalidValue, unusedBits)
	}
	if len(value) == 1 && unusedBits != 0 {
		return nil, 0, fmt.Errorf("%w: BIT STRING unused bits %d with no content bytes", ErrInvalidValue, unusedBits)
	}
	return value[1:], unusedBits, nil
}

// DecodeStringValue returns raw value bytes as a string.
func DecodeStringValue(value []byte) string {
	return string(value)
}

// DecodeRealValue decodes a REAL from raw value bytes.
func DecodeRealValue(value []byte) (float64, error) {
	if len(value) == 0 {
		return 0.0, nil
	}
	info := value[0]
	if info&0x80 != 0 {
		// Binary encoding.
		sign := 1.0
		if info&0x40 != 0 {
			sign = -1.0
		}
		base := 2.0
		switch (info >> 4) & 0x03 {
		case 1:
			base = 8.0
		case 2:
			base = 16.0
		}
		scaleFactor := int((info >> 2) & 0x03)
		expLen := int(info&0x03) + 1
		if 1+expLen > len(value) {
			return 0, fmt.Errorf("%w: REAL exponent truncated", ErrInvalidValue)
		}
		var exp int64
		if value[1]&0x80 != 0 {
			exp = -1
		}
		for i := 1; i <= expLen; i++ {
			exp = (exp << 8) | int64(value[i])
		}
		var mantissa uint64
		for i := 1 + expLen; i < len(value); i++ {
			mantissa = (mantissa << 8) | uint64(value[i])
		}
		return sign * float64(mantissa) * math.Pow(2, float64(scaleFactor)) * math.Pow(base, float64(exp)), nil
	}
	if info == 0x40 {
		return math.Inf(1), nil
	}
	if info == 0x41 {
		return math.Inf(-1), nil
	}
	return 0, fmt.Errorf("%w: unsupported REAL encoding", ErrInvalidValue)
}

// DecodeOIDValue decodes an OID from raw value bytes.
func DecodeOIDValue(value []byte) ([]uint64, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty OID value", ErrInvalidValue)
	}
	result := make([]uint64, 0, 8)
	first, offset := decodeBase128(value, 0)
	if offset == 0 {
		return nil, fmt.Errorf("%w: invalid OID first subidentifier encoding", ErrInvalidValue)
	}
	if first >= 80 {
		result = append(result, 2, first-80)
	} else {
		result = append(result, first/40, first%40)
	}
	for offset < len(value) {
		v, consumed := decodeBase128(value, offset)
		if consumed <= offset {
			return nil, fmt.Errorf("%w: invalid OID base-128 encoding", ErrInvalidValue)
		}
		result = append(result, v)
		offset = consumed
	}
	return result, nil
}

// SkipTLV skips one complete TLV in data and returns the number of bytes consumed.
func SkipTLV(data []byte) (int, error) {
	_, total, _, err := DecodeTLV(data)
	return total, err
}

// DecodeSequenceContent decodes the outer SEQUENCE tag and returns the content bytes
// and total bytes consumed. This is used by generated UnmarshalBER methods.
func DecodeSequenceContent(data []byte) ([]byte, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagSequence || !t.Constructed {
		return nil, 0, fmt.Errorf("%w: expected SEQUENCE, got %s", ErrInvalidTag, t)
	}
	return value, total, nil
}

// DecodeConstructedContent decodes any constructed TLV and returns the content bytes,
// the tag, and total bytes consumed. Used for APPLICATION-tagged types.
func DecodeConstructedContent(data []byte) (tag.Tag, []byte, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return tag.Tag{}, nil, 0, err
	}
	return t, value, total, nil
}
