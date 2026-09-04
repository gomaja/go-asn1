package ber

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// EncodeLength serializes a BER/DER length field.
// For DER, this always uses the shortest definite form.
func EncodeLength(length int) []byte {
	if length < 0 {
		// Indefinite length: 0x80 (BER only, not DER).
		return []byte{0x80}
	}
	if length < 128 {
		return []byte{byte(length)}
	}
	// Long form: first byte = 0x80 | number of subsequent length bytes.
	var buf []byte
	n := length
	for n > 0 {
		buf = append([]byte{byte(n & 0xFF)}, buf...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}

// EncodeTLV assembles a complete TLV (Tag-Length-Value).
func EncodeTLV(t tag.Tag, value []byte) []byte {
	tagBytes := t.Encode()
	lenBytes := EncodeLength(len(value))
	result := make([]byte, 0, len(tagBytes)+len(lenBytes)+len(value))
	result = append(result, tagBytes...)
	result = append(result, lenBytes...)
	result = append(result, value...)
	return result
}

// EncodeBoolean encodes a boolean value per X.690 section 8.2.
func EncodeBoolean(v bool) []byte {
	if v {
		return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}, []byte{0xFF})
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}, []byte{0x00})
}

// EncodeInteger encodes an integer value per X.690 section 8.3.
// Uses two's complement with minimal octets.
func EncodeInteger(v int64) []byte {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagInteger},
		encodeIntBytes(v),
	)
}

func encodeIntBytes(v int64) []byte {
	if v == 0 {
		return []byte{0x00}
	}

	// Work with big-endian two's complement bytes.
	uv := uint64(v)

	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = byte(uv & 0xFF)
		uv >>= 8
	}

	// Strip leading 0x00 or 0xFF bytes, keeping minimal encoding.
	start := 0
	if v >= 0 {
		for start < 7 && buf[start] == 0 && buf[start+1]&0x80 == 0 {
			start++
		}
	} else {
		for start < 7 && buf[start] == 0xFF && buf[start+1]&0x80 != 0 {
			start++
		}
	}

	return buf[start:]
}

// EncodeBigInt encodes a *big.Int per X.690 section 8.3.
func EncodeBigInt(v *big.Int) []byte {
	if v == nil {
		return EncodeInteger(0)
	}
	b := v.Bytes() // absolute value, big-endian
	if v.Sign() >= 0 {
		// Add leading zero if high bit is set.
		if len(b) == 0 {
			b = []byte{0x00}
		} else if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
	} else {
		// Two's complement for negative: invert and add 1.
		// Use big.Int's Bytes on the positive value, then compute two's complement.
		pos := new(big.Int).Neg(v)
		pb := pos.Bytes()
		// Allocate enough space.
		tc := make([]byte, len(pb))
		// Subtract 1 from positive, then invert all bits.
		borrow := byte(1)
		for i := len(pb) - 1; i >= 0; i-- {
			val := pb[i] - borrow
			if pb[i] >= borrow {
				borrow = 0
			} else {
				borrow = 1
				val = 0xFF - (borrow - 1 - pb[i])
			}
			tc[i] = ^val
		}
		// Ensure high bit is set.
		if len(tc) == 0 || tc[0]&0x80 == 0 {
			tc = append([]byte{0xFF}, tc...)
		}
		b = tc
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagInteger}, b)
}

// EncodeBitString encodes a bit string per X.690 section 8.6.
// unusedBits is the number of unused bits in the last byte (0-7).
func EncodeBitString(bytes []byte, unusedBits int) []byte {
	if len(bytes) == 0 {
		return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}, []byte{0x00})
	}
	value := make([]byte, 1+len(bytes))
	value[0] = byte(unusedBits)
	copy(value[1:], bytes)
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}, value)
}

// EncodeOctetString encodes an octet string per X.690 section 8.7.
func EncodeOctetString(v []byte) []byte {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagOctetString}, v)
}

// EncodeNull encodes a NULL value per X.690 section 8.8.
func EncodeNull() []byte {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagNull}, nil)
}

// EncodeObjectIdentifier encodes an OID per X.690 section 8.19. Invalid
// values return nil; generated code uses EncodeObjectIdentifierChecked so it
// can report the validation error.
func EncodeObjectIdentifier(oid []uint64) []byte {
	encoded, err := EncodeObjectIdentifierChecked(oid)
	if err != nil {
		return nil
	}
	return encoded
}

// EncodeObjectIdentifierChecked encodes a validated OID per X.690
// (02/2021) section 8.19.4.
func EncodeObjectIdentifierChecked(oid []uint64) ([]byte, error) {
	value, err := EncodeOIDValueChecked(oid)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagObjectID}, value), nil
}

// EncodeRelativeObjectIdentifierChecked encodes a validated RELATIVE-OID per
// X.690 (02/2021) section 8.20.
func EncodeRelativeObjectIdentifierChecked(oid []uint64) ([]byte, error) {
	value, err := EncodeRelativeOIDValueChecked(oid)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagRelativeOID}, value), nil
}

func encodeBase128(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var buf []byte
	for v > 0 {
		buf = append([]byte{byte(v & 0x7F)}, buf...)
		v >>= 7
	}
	for i := 0; i < len(buf)-1; i++ {
		buf[i] |= 0x80
	}
	return buf
}

// EncodeEnumerated encodes an enumerated value per X.690 section 8.4.
func EncodeEnumerated(v int64) []byte {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagEnumerated},
		encodeIntBytes(v),
	)
}

// EncodeReal encodes an exact REAL value per X.690 (02/2021), sections 8.5
// and 11.3. Finite output is DER-canonical and therefore valid BER.
func EncodeReal(value runtime.Real) ([]byte, error) {
	contents, err := EncodeRealValue(value)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents), nil
}

// EncodeRealValue returns the canonical contents octets of an ASN.1 REAL.
func EncodeRealValue(value runtime.Real) ([]byte, error) {
	canonical, err := value.Canonical()
	if err != nil {
		return nil, err
	}
	switch canonical.Kind {
	case runtime.RealPlusInfinity:
		return []byte{0x40}, nil
	case runtime.RealMinusInfinity:
		return []byte{0x41}, nil
	case runtime.RealNotANumber:
		return []byte{0x42}, nil
	case runtime.RealMinusZero:
		return []byte{0x43}, nil
	}
	if canonical.Mantissa == nil {
		return nil, nil
	}

	if canonical.Base == 10 {
		exponent := canonical.Exponent.String()
		if canonical.Exponent.Sign() == 0 {
			exponent = "+0"
		}
		return []byte("\x03" + canonical.Mantissa.String() + ".E" + exponent), nil
	}

	mantissa := new(big.Int).Set(canonical.Mantissa)
	info := byte(0x80)
	if mantissa.Sign() < 0 {
		info |= 0x40
		mantissa.Abs(mantissa)
	}
	exponent := EncodeBigIntValue(canonical.Exponent)
	if len(exponent) > 255 {
		return nil, fmt.Errorf("%w: REAL exponent requires %d octets, maximum is 255", ErrInvalidValue, len(exponent))
	}
	switch len(exponent) {
	case 1:
	case 2:
		info |= 0x01
	case 3:
		info |= 0x02
	default:
		info |= 0x03
	}
	contents := []byte{info}
	if len(exponent) > 3 {
		contents = append(contents, byte(len(exponent)))
	}
	contents = append(contents, exponent...)
	contents = append(contents, mantissa.Bytes()...)
	return contents, nil
}

// EncodeUTF8String encodes a UTF8String.
func EncodeUTF8String(v string) []byte {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagUTF8String}, []byte(v))
}

// EncodeIA5String encodes an IA5String.
func EncodeIA5String(v string) []byte {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagIA5String}, []byte(v))
}

// EncodePrintableString encodes a PrintableString.
func EncodePrintableString(v string) []byte {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagPrintableString}, []byte(v))
}

// EncodeStringTag encodes a character string value under an arbitrary
// UNIVERSAL tag number. Invalid values return nil; generated code uses
// EncodeStringTagChecked so it can report the validation error.
func EncodeStringTag(tagNum int, v string) []byte {
	encoded, err := EncodeStringTagChecked(tagNum, v)
	if err != nil {
		return nil
	}
	return encoded
}

// EncodeStringTagChecked applies the fixed-width forms required by X.690
// (02/2021) sections 8.23.7 and 8.23.8 before wrapping the value.
func EncodeStringTagChecked(tagNum int, v string) ([]byte, error) {
	value, err := EncodeStringValueTagChecked(tagNum, v)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tagNum}, value), nil
}

// EncodeStringValueTagChecked returns the contents octets for a restricted
// character string with the supplied UNIVERSAL tag number.
func EncodeStringValueTagChecked(tagNum int, v string) ([]byte, error) {
	return encodeStringValueTag(tagNum, v)
}

func encodeStringValueTag(tagNum int, v string) ([]byte, error) {
	switch tagNum {
	case tag.TagBMPString:
		if !utf8.ValidString(v) {
			return nil, fmt.Errorf("BMPString contains invalid UTF-8")
		}
		value := make([]byte, 0, len(v)*2)
		for _, r := range v {
			if r > 0xffff || !utf8.ValidRune(r) {
				return nil, fmt.Errorf("BMPString character U+%04X is outside the Basic Multilingual Plane", r)
			}
			value = binary.BigEndian.AppendUint16(value, uint16(r))
		}
		return value, nil
	case tag.TagUniversalString:
		if !utf8.ValidString(v) {
			return nil, fmt.Errorf("UniversalString contains invalid UTF-8")
		}
		value := make([]byte, 0, len(v)*4)
		for _, r := range v {
			if !utf8.ValidRune(r) {
				return nil, fmt.Errorf("UniversalString character U+%04X is not a Unicode scalar value", r)
			}
			value = binary.BigEndian.AppendUint32(value, uint32(r))
		}
		return value, nil
	default:
		return []byte(v), nil
	}
}

// EncodeUTCTime encodes a UTCTime per X.690 section 11.8.
func EncodeUTCTime(t time.Time) []byte {
	utc := t.UTC()
	s := utc.Format("060102150405Z")
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagUTCTime}, []byte(s))
}

// EncodeGeneralizedTime encodes a GeneralizedTime per X.690 section 11.7.
func EncodeGeneralizedTime(t time.Time) []byte {
	utc := t.UTC()
	s := utc.Format("20060102150405Z")
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagGeneralizedTime}, []byte(s))
}

// EncodeSequence encodes a SEQUENCE (constructed) from pre-encoded children.
func EncodeSequence(children []byte) []byte {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true},
		children,
	)
}

// EncodeConstructedIndefinite encodes a constructed TLV using BER indefinite length form.
// This produces: tag bytes + 0x80 + children + 0x00 0x00.
func EncodeConstructedIndefinite(t tag.Tag, children []byte) []byte {
	t.Constructed = true
	tagBytes := t.Encode()
	result := make([]byte, 0, len(tagBytes)+1+len(children)+2)
	result = append(result, tagBytes...)
	result = append(result, 0x80) // indefinite length
	result = append(result, children...)
	result = append(result, 0x00, 0x00) // end-of-contents
	return result
}

// EncodeSet encodes a SET (constructed) from pre-encoded children.
// For DER, children should be sorted by tag before calling this.
func EncodeSet(children []byte) []byte {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSet, Constructed: true},
		children,
	)
}

// EncodeDERSet orders complete DER component encodings by tag and wraps them
// in a SET. ITU-T X.690 (02/2021) Section 10.3.
func EncodeDERSet(children []byte) ([]byte, error) {
	elements, err := splitDERElements(children)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(elements, func(left, right int) bool {
		if elements[left].tag.Class != elements[right].tag.Class {
			return elements[left].tag.Class < elements[right].tag.Class
		}
		return elements[left].tag.Number < elements[right].tag.Number
	})
	return EncodeSet(joinDERElements(elements)), nil
}

// EncodeDERSetOf orders complete DER element encodings as padded octet
// strings and wraps them in a SET. ITU-T X.690 (02/2021) Section 11.6.
func EncodeDERSetOf(children []byte) ([]byte, error) {
	elements, err := splitDERElements(children)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(elements, func(left, right int) bool {
		return compareDEROctetStrings(elements[left].encoded, elements[right].encoded) < 0
	})
	return EncodeSet(joinDERElements(elements)), nil
}

type derElement struct {
	tag     tag.Tag
	encoded []byte
}

func splitDERElements(children []byte) ([]derElement, error) {
	var elements []derElement
	for offset := 0; offset < len(children); {
		decodedTag, total, _, err := DecodeTLV(children[offset:])
		if err != nil {
			return nil, fmt.Errorf("DER SET element at offset %d: %w", offset, err)
		}
		encoded := children[offset : offset+total]
		if err := ValidateDERElement(encoded); err != nil {
			return nil, fmt.Errorf("DER SET element at offset %d: %w", offset, err)
		}
		elements = append(elements, derElement{tag: decodedTag, encoded: encoded})
		offset += total
	}
	return elements, nil
}

func joinDERElements(elements []derElement) []byte {
	length := 0
	for _, element := range elements {
		length += len(element.encoded)
	}
	joined := make([]byte, 0, length)
	for _, element := range elements {
		joined = append(joined, element.encoded...)
	}
	return joined
}

// EncodeExplicitTag wraps encoded content in an explicit context-specific tag.
func EncodeExplicitTag(tagNum int, content []byte) []byte {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassContextSpecific, Number: tagNum, Constructed: true},
		content,
	)
}

// EncodeExplicitTagWithClass wraps encoded content in an explicit tag with the given class.
func EncodeExplicitTagWithClass(tagClass tag.Class, tagNum int, content []byte) []byte {
	return EncodeTLV(
		tag.Tag{Class: tagClass, Number: tagNum, Constructed: true},
		content,
	)
}

// EncodeImplicitTag replaces the outer tag with a context-specific tag while
// preserving the encoded value's primitive or constructed form and length.
func EncodeImplicitTag(tagNum int, content []byte) ([]byte, error) {
	return EncodeImplicitTagWithClass(tag.ClassContextSpecific, tagNum, content)
}

// EncodeImplicitTagWithClass replaces the outer tag while preserving the
// encoded value's primitive or constructed form and original length encoding.
func EncodeImplicitTagWithClass(tagClass tag.Class, tagNum int, content []byte) ([]byte, error) {
	if tagClass > tag.ClassPrivate || tagNum < 0 {
		return nil, fmt.Errorf("%w: invalid implicit tag class %d number %d", ErrInvalidTag, tagClass, tagNum)
	}
	decodedTag, tagLength, err := DecodeTag(content)
	if err != nil {
		return nil, fmt.Errorf("retag implicit value: %w", err)
	}
	_, total, _, err := DecodeTLV(content)
	if err != nil {
		return nil, fmt.Errorf("retag implicit value: %w", err)
	}
	if total != len(content) {
		return nil, fmt.Errorf("%w: implicit value has %d trailing octets", ErrInvalidValue, len(content)-total)
	}
	replacement := tag.Tag{Class: tagClass, Number: tagNum, Constructed: decodedTag.Constructed}.Encode()
	encoded := make([]byte, 0, len(replacement)+len(content)-tagLength)
	encoded = append(encoded, replacement...)
	encoded = append(encoded, content[tagLength:]...)
	return encoded, nil
}

// EncodeConstructed encodes a constructed TLV with a custom tag.
func EncodeConstructed(t tag.Tag, children []byte) []byte {
	t.Constructed = true
	return EncodeTLV(t, children)
}

// --- Value-level encoders for generated code ---
// These produce only the value bytes (no tag+length), for use with implicit tagging
// or when the caller constructs the TLV envelope.

// EncodeIntegerValue returns the raw value bytes for an integer.
func EncodeIntegerValue(v int64) []byte {
	return encodeIntBytes(v)
}

// EncodeBooleanValue returns the raw value byte for a boolean (DER: 0xFF for true).
func EncodeBooleanValue(v bool) []byte {
	if v {
		return []byte{0xFF}
	}
	return []byte{0x00}
}

// EncodeBooleanRaw encodes a boolean TLV using the provided raw value byte.
// This preserves byte-exact BER round-trip when TRUE was encoded as a non-0xFF value.
func EncodeBooleanRaw(rawByte byte) []byte {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}, []byte{rawByte})
}

// EncodeBitStringValue returns the raw value bytes for a bit string.
func EncodeBitStringValue(bytes []byte, unusedBits int) []byte {
	result := make([]byte, 1+len(bytes))
	result[0] = byte(unusedBits)
	copy(result[1:], bytes)
	return result
}

// EncodeOIDValue returns the raw value bytes for an OID. Invalid values return
// nil; generated code and PER use EncodeOIDValueChecked to retain the error.
func EncodeOIDValue(oid []uint64) []byte {
	encoded, err := EncodeOIDValueChecked(oid)
	if err != nil {
		return nil
	}
	return encoded
}

// EncodeOIDValueChecked returns the X.690 section 8.19 contents octets after
// validating the first two arcs and their packed uint64 representation.
func EncodeOIDValueChecked(oid []uint64) ([]byte, error) {
	if len(oid) < 2 {
		return nil, fmt.Errorf("object identifier needs at least 2 arcs, got %d", len(oid))
	}
	if oid[0] > 2 {
		return nil, fmt.Errorf("object identifier first arc %d exceeds 2", oid[0])
	}
	if oid[0] < 2 && oid[1] > 39 {
		return nil, fmt.Errorf("object identifier second arc %d exceeds 39 under first arc %d", oid[1], oid[0])
	}
	if oid[0] == 2 && oid[1] > math.MaxUint64-80 {
		return nil, fmt.Errorf("object identifier first subidentifier overflows uint64")
	}
	var buf []byte
	first := oid[0]*40 + oid[1]
	buf = append(buf, encodeBase128(first)...)
	for _, arc := range oid[2:] {
		buf = append(buf, encodeBase128(arc)...)
	}
	return buf, nil
}

// EncodeRelativeOIDValueChecked returns the X.690 section 8.20 contents
// octets. X.680 (02/2021) section 33.3 requires at least one arc.
func EncodeRelativeOIDValueChecked(oid []uint64) ([]byte, error) {
	if len(oid) == 0 {
		return nil, fmt.Errorf("relative object identifier needs at least 1 arc")
	}
	var value []byte
	for _, arc := range oid {
		value = append(value, encodeBase128(arc)...)
	}
	return value, nil
}

// EncodeStringValue returns the raw value bytes for a string.
func EncodeStringValue(s string) []byte {
	return []byte(s)
}

// EncodeBigIntValue returns only the X.690 §8.3 contents octets for an
// arbitrary-width INTEGER, without the tag and length. Components inside a
// SEQUENCE are assembled from value-level encoders, so this is the
// arbitrary-precision counterpart to EncodeIntegerValue.
func EncodeBigIntValue(v *big.Int) []byte {
	full := EncodeBigInt(v)
	// EncodeBigInt emits tag + length + contents; the contents start after
	// the 1-octet universal INTEGER tag and its length field.
	_, _, value, err := DecodeTLV(full)
	if err != nil {
		// EncodeBigInt always produces a well-formed TLV, so this is
		// unreachable; return the whole thing rather than silently dropping
		// the value if that ever stops being true.
		return full
	}
	return value
}
