package ber

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

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
		if !t.Constructed {
			return tag.Tag{}, 0, nil, fmt.Errorf("%w: indefinite length used with primitive tag %s", ErrInvalidLength, t)
		}
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

// ValidateDERElement verifies that data contains exactly one DER TLV.
func ValidateDERElement(data []byte) error {
	n, err := ValidateDERTLV(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return ErrExtraData
	}
	return nil
}

// ValidateDERTLV verifies one definite-length DER TLV and returns its size.
func ValidateDERTLV(data []byte) (int, error) {
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return 0, err
	}
	length, indefinite, lenLen, err := DecodeLength(data[tagLen:])
	if err != nil {
		return 0, err
	}
	if indefinite {
		return 0, ErrIndefiniteLength
	}

	headerLen := tagLen + lenLen
	end := headerLen + length
	if end > len(data) {
		return 0, ErrTruncated
	}
	if t.Constructed {
		offset := headerLen
		var previous []byte
		for offset < end {
			n, err := ValidateDERTLV(data[offset:end])
			if err != nil {
				return 0, err
			}
			current := data[offset : offset+n]
			if t.Class == tag.ClassUniversal && t.Number == tag.TagSet && previous != nil && compareDEROctetStrings(previous, current) > 0 {
				return 0, fmt.Errorf("%w: DER SET components are not in canonical order", ErrInvalidValue)
			}
			previous = current
			offset += n
		}
	}
	return end, nil
}

func compareDEROctetStrings(left, right []byte) int {
	length := max(len(left), len(right))
	for index := 0; index < length; index++ {
		var leftOctet, rightOctet byte
		if index < len(left) {
			leftOctet = left[index]
		}
		if index < len(right) {
			rightOctet = right[index]
		}
		if leftOctet < rightOctet {
			return -1
		}
		if leftOctet > rightOctet {
			return 1
		}
	}
	return 0
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
	if t.Constructed {
		return false, 0, 0, fmt.Errorf("%w: BOOLEAN must be primitive, got constructed", ErrInvalidTag)
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
	if t.Class != tag.ClassUniversal || t.Number != tag.TagInteger {
		return 0, 0, fmt.Errorf("%w: expected INTEGER tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return 0, 0, fmt.Errorf("%w: INTEGER must be primitive, got constructed", ErrInvalidTag)
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
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: INTEGER must be primitive, got constructed", ErrInvalidTag)
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
	decoded, unusedBits, err := decodeBitStringValue(t.Constructed, value)
	return decoded, unusedBits, total, err
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
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: OBJECT IDENTIFIER must be primitive", ErrInvalidTag)
	}
	if len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: OBJECT IDENTIFIER content must contain at least one subidentifier", ErrInvalidValue)
	}

	// Decode first two components.
	firstVal, offset, err := decodeBase128(value, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding OID first subidentifier: %w", err)
	}
	var oid []uint64
	if firstVal < 80 {
		oid = append(oid, firstVal/40, firstVal%40)
	} else {
		oid = append(oid, 2, firstVal-80)
	}

	// Decode remaining components.
	for offset < len(value) {
		v, newOffset, err := decodeBase128(value, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding OID subidentifier: %w", err)
		}
		oid = append(oid, v)
		offset = newOffset
	}

	return oid, total, nil
}

// DecodeRelativeObjectIdentifier decodes a RELATIVE-OID per X.690
// (02/2021) section 8.20.
func DecodeRelativeObjectIdentifier(data []byte) ([]uint64, int, error) {
	t, total, value, err := DecodeTLV(data)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagRelativeOID {
		return nil, 0, fmt.Errorf("%w: expected RELATIVE-OID tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: RELATIVE-OID must be primitive", ErrInvalidTag)
	}
	oid, err := DecodeRelativeOIDValue(value)
	if err != nil {
		return nil, 0, err
	}
	return oid, total, nil
}

func decodeBase128(data []byte, offset int) (uint64, int, error) {
	var v uint64
	start := offset
	for offset < len(data) {
		b := data[offset]
		offset++
		if offset == start+1 && b == 0x80 && offset < len(data) {
			return 0, offset, fmt.Errorf("%w: non-minimal base-128 subidentifier", ErrInvalidValue)
		}
		bits := uint64(b & 0x7f)
		if v > math.MaxUint64>>7 || v == math.MaxUint64>>7 && bits > math.MaxUint64&0x7f {
			return 0, offset, fmt.Errorf("%w: base-128 subidentifier overflows uint64", ErrInvalidValue)
		}
		v = (v << 7) | bits
		if b&0x80 == 0 {
			return v, offset, nil
		}
	}
	if offset == start {
		return 0, offset, fmt.Errorf("%w: empty base-128 encoding", ErrInvalidValue)
	}
	return 0, offset, fmt.Errorf("%w: truncated base-128 encoding", ErrTruncated)
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
	if t.Constructed {
		return 0, 0, fmt.Errorf("%w: ENUMERATED must be primitive, got constructed", ErrInvalidTag)
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
	if info == 0x43 {
		return math.Copysign(0, -1), total, nil
	}

	if info&0x80 == 0 {
		return 0, 0, fmt.Errorf("%w: decimal/character REAL encoding not supported", ErrUnsupported)
	}

	// Binary encoding.
	sign := (info >> 6) & 1
	baseField := (info >> 4) & 3
	scaleFactor := (info >> 2) & 3
	expLen := int(info&3) + 1

	var baseValue float64
	switch baseField {
	case 0:
		baseValue = 2.0
	case 1:
		baseValue = 8.0
	case 2:
		baseValue = 16.0
	default:
		return 0, 0, fmt.Errorf("%w: REAL base field %d invalid", ErrInvalidValue, baseField)
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

	// Result = (-1)^sign * mantissa * 2^scaleFactor * base^exponent
	result := float64(mantissa) * math.Pow(2, float64(scaleFactor)) * math.Pow(baseValue, float64(exp))
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
	if t.Constructed {
		var decoded strings.Builder
		for offset := 0; offset < len(value); {
			part, consumed, err := DecodeString(value[offset:], expectedTag)
			if err != nil {
				return "", 0, fmt.Errorf("decoding constructed string component: %w", err)
			}
			if consumed <= 0 {
				return "", 0, fmt.Errorf("%w: constructed string component consumed no input", ErrInvalidValue)
			}
			decoded.WriteString(part)
			offset += consumed
		}
		return decoded.String(), total, nil
	}
	decoded, err := DecodeStringValueTag(expectedTag, value)
	if err != nil {
		return "", 0, err
	}
	return decoded, total, nil
}

// DecodeUTCTime decodes a UTCTime value from raw TLV bytes.
func DecodeUTCTime(data []byte) (time.Time, int, error) {
	s, total, err := DecodeString(data, tag.TagUTCTime)
	if err != nil {
		return time.Time{}, 0, err
	}
	t, err := parseUTCTime(s)
	if err != nil {
		return time.Time{}, 0, err
	}
	return t, total, nil
}

// DecodeGeneralizedTime decodes a GeneralizedTime value from raw TLV bytes.
func DecodeGeneralizedTime(data []byte) (time.Time, int, error) {
	s, total, err := DecodeString(data, tag.TagGeneralizedTime)
	if err != nil {
		return time.Time{}, 0, err
	}
	t, err := parseGeneralizedTime(s)
	if err != nil {
		return time.Time{}, 0, err
	}
	return t, total, nil
}

// DecodeUTCTimeValue decodes a UTCTime from raw value bytes (tag/length
// already consumed by the caller — e.g. an implicitly tagged field, where
// the wrapping tag replaced the UNIVERSAL UTCTime tag, or a CHOICE
// alternative whose tag has already been matched).
func DecodeUTCTimeValue(value []byte) (time.Time, error) {
	return parseUTCTime(string(value))
}

// DecodeGeneralizedTimeValue decodes a GeneralizedTime from raw value bytes
// (tag/length already consumed by the caller — see DecodeUTCTimeValue).
func DecodeGeneralizedTimeValue(value []byte) (time.Time, error) {
	return parseGeneralizedTime(string(value))
}

// parseUTCTime parses the character content of an ASN.1 UTCTime.
func parseUTCTime(s string) (time.Time, error) {
	// Try common formats.
	for _, layout := range []string{
		"060102150405Z",
		"0601021504Z",
		"060102150405-0700",
		"060102150405+0700",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			// ASN.1 UTCTime: YY >= 50 → 19YY, YY < 50 → 20YY.
			// Go's time.Parse uses cutoff 69, so years 50-68 are wrong.
			year := t.Year()
			if year >= 2050 && year <= 2068 {
				t = t.AddDate(-100, 0, 0)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: cannot parse UTCTime %q", ErrInvalidValue, s)
}

// parseGeneralizedTime parses the character content of an ASN.1 GeneralizedTime.
func parseGeneralizedTime(s string) (time.Time, error) {
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405",
		"20060102150405.000Z",
		"20060102150405-0700",
		"20060102150405+0700",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: cannot parse GeneralizedTime %q", ErrInvalidValue, s)
}

// DecodeRawValue reads one complete TLV without interpreting the value.
// Returns the tag, raw value bytes, and total bytes consumed.
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

// DecodeEnumeratedValue decodes primitive ENUMERATED contents after its tag
// and length have been consumed by an implicit-tag decoder.
func DecodeEnumeratedValue(value []byte) (int64, error) {
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
	return decodePrimitiveBitStringValue(value)
}

// DecodeImplicitBitStringValue decodes primitive or constructed BIT STRING
// contents after an implicit tag has been consumed. X.690 (02/2021) 8.6.1
// permits both forms and 8.6.4.1 requires recursive, ordered segments.
func DecodeImplicitBitStringValue(constructed bool, value []byte) ([]byte, int, error) {
	return decodeBitStringValue(constructed, value)
}

func decodeBitStringValue(constructed bool, value []byte) ([]byte, int, error) {
	if !constructed {
		return decodePrimitiveBitStringValue(value)
	}

	children, err := DecodeSequenceChildren(value)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding constructed BIT STRING: %w", err)
	}
	var result []byte
	unusedBits := 0
	for index, child := range children {
		segment, segmentUnused, consumed, err := DecodeBitString(child)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding constructed BIT STRING segment %d: %w", index, err)
		}
		if consumed != len(child) {
			return nil, 0, fmt.Errorf("decoding constructed BIT STRING segment %d: %w", index, ErrExtraData)
		}
		if index != len(children)-1 && segmentUnused != 0 {
			return nil, 0, fmt.Errorf("%w: BIT STRING segment %d has %d unused bits before the final segment", ErrInvalidValue, index, segmentUnused)
		}
		result = append(result, segment...)
		unusedBits = segmentUnused
	}
	return result, unusedBits, nil
}

func decodePrimitiveBitStringValue(value []byte) ([]byte, int, error) {
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

// DecodeStringValueTag decodes restricted-character-string contents according
// to the supplied UNIVERSAL tag number. X.690 (02/2021) sections 8.23.7 and
// 8.23.8 require four-octet UniversalString and two-octet BMPString forms.
func DecodeStringValueTag(tagNum int, value []byte) (string, error) {
	switch tagNum {
	case tag.TagBMPString:
		if len(value)%2 != 0 {
			return "", fmt.Errorf("%w: BMPString content length %d is not divisible by 2", ErrInvalidValue, len(value))
		}
		runes := make([]rune, 0, len(value)/2)
		for offset := 0; offset < len(value); offset += 2 {
			r := rune(binary.BigEndian.Uint16(value[offset : offset+2]))
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("%w: BMPString contains invalid code point U+%04X", ErrInvalidValue, r)
			}
			runes = append(runes, r)
		}
		return string(runes), nil
	case tag.TagUniversalString:
		if len(value)%4 != 0 {
			return "", fmt.Errorf("%w: UniversalString content length %d is not divisible by 4", ErrInvalidValue, len(value))
		}
		runes := make([]rune, 0, len(value)/4)
		for offset := 0; offset < len(value); offset += 4 {
			r := rune(binary.BigEndian.Uint32(value[offset : offset+4]))
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("%w: UniversalString contains invalid code point U+%04X", ErrInvalidValue, r)
			}
			runes = append(runes, r)
		}
		return string(runes), nil
	default:
		return string(value), nil
	}
}

// DecodeImplicitStringValue decodes the contents of an implicitly tagged
// restricted character string while preserving BER's primitive or constructed form.
func DecodeImplicitStringValue(tagNum int, constructed bool, value []byte) (string, error) {
	if !constructed {
		return DecodeStringValueTag(tagNum, value)
	}
	reconstructed := EncodeConstructed(tag.Tag{Class: tag.ClassUniversal, Number: tagNum}, value)
	decoded, total, err := DecodeString(reconstructed, tagNum)
	if err != nil {
		return "", err
	}
	if total != len(reconstructed) {
		return "", ErrExtraData
	}
	return decoded, nil
}

// DecodeImplicitUTCTimeValue decodes primitive or constructed implicitly tagged UTCTime contents.
func DecodeImplicitUTCTimeValue(constructed bool, value []byte) (time.Time, error) {
	decoded, err := DecodeImplicitStringValue(tag.TagUTCTime, constructed, value)
	if err != nil {
		return time.Time{}, err
	}
	return parseUTCTime(decoded)
}

// DecodeImplicitGeneralizedTimeValue decodes primitive or constructed implicitly tagged GeneralizedTime contents.
func DecodeImplicitGeneralizedTimeValue(constructed bool, value []byte) (time.Time, error) {
	decoded, err := DecodeImplicitStringValue(tag.TagGeneralizedTime, constructed, value)
	if err != nil {
		return time.Time{}, err
	}
	return parseGeneralizedTime(decoded)
}

// DecodeRealValue decodes a REAL from raw value bytes.
func DecodeRealValue(value []byte) (float64, error) {
	if len(value) == 0 {
		return 0.0, nil
	}
	info := value[0]

	// Special values.
	if info == 0x40 {
		return math.Inf(1), nil
	}
	if info == 0x41 {
		return math.Inf(-1), nil
	}
	if info == 0x42 {
		return math.NaN(), nil
	}
	if info == 0x43 {
		return math.Copysign(0, -1), nil
	}

	if info&0x80 == 0 {
		return 0, fmt.Errorf("%w: decimal/character REAL encoding not supported", ErrInvalidValue)
	}

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

	offset := 1
	if info&0x03 == 3 {
		// Long exponent form: next byte gives actual exponent length.
		if offset >= len(value) {
			return 0, fmt.Errorf("%w: REAL exponent length truncated", ErrInvalidValue)
		}
		expLen = int(value[offset])
		offset++
	}

	if offset+expLen > len(value) {
		return 0, fmt.Errorf("%w: REAL exponent truncated", ErrInvalidValue)
	}
	var exp int64
	if value[offset]&0x80 != 0 {
		exp = -1
	}
	for i := offset; i < offset+expLen; i++ {
		exp = (exp << 8) | int64(value[i])
	}
	offset += expLen

	var mantissa uint64
	for i := offset; i < len(value); i++ {
		mantissa = (mantissa << 8) | uint64(value[i])
	}
	return sign * float64(mantissa) * math.Pow(2, float64(scaleFactor)) * math.Pow(base, float64(exp)), nil
}

// DecodeOIDValue decodes an OID from raw value bytes.
func DecodeOIDValue(value []byte) ([]uint64, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty OID value", ErrInvalidValue)
	}
	result := make([]uint64, 0, 8)
	first, offset, err := decodeBase128(value, 0)
	if err != nil {
		return nil, fmt.Errorf("decoding OID first subidentifier: %w", err)
	}
	if first >= 80 {
		result = append(result, 2, first-80)
	} else {
		result = append(result, first/40, first%40)
	}
	for offset < len(value) {
		v, consumed, err := decodeBase128(value, offset)
		if err != nil {
			return nil, fmt.Errorf("decoding OID subidentifier: %w", err)
		}
		result = append(result, v)
		offset = consumed
	}
	return result, nil
}

// DecodeRelativeOIDValue decodes X.690 section 8.20 contents octets.
func DecodeRelativeOIDValue(value []byte) ([]uint64, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty RELATIVE-OID value", ErrInvalidValue)
	}
	oid := make([]uint64, 0, 4)
	for offset := 0; offset < len(value); {
		arc, next, err := decodeBase128(value, offset)
		if err != nil {
			return nil, fmt.Errorf("decoding RELATIVE-OID subidentifier: %w", err)
		}
		oid = append(oid, arc)
		offset = next
	}
	return oid, nil
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

// DecodeBigIntValue interprets contents octets as an arbitrary-width INTEGER.
//
// It is the counterpart to DecodeIntegerValue, which caps at 8 octets because
// its result is an int64. An ASN.1 INTEGER is unbounded, and unconstrained
// ones legitimately exceed 64 bits: RFC 5280 §4.1.2.2 requires certificate
// users to handle a serialNumber of up to 20 octets.
func DecodeBigIntValue(value []byte) (*big.Int, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty integer", ErrInvalidValue)
	}
	v := new(big.Int)
	if value[0]&0x80 != 0 {
		notBytes := make([]byte, len(value))
		for i, b := range value {
			notBytes[i] = ^b
		}
		v.SetBytes(notBytes)
		v.Add(v, big.NewInt(1))
		v.Neg(v)
		return v, nil
	}
	v.SetBytes(value)
	return v, nil
}
