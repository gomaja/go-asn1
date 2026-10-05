package ber

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	mathbits "math/bits"
	"sort"
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
	// A host int needs at most eight octets. Keep the length-of-length
	// octet constant so its byte width is independent of the input value.
	lengthPrefixes := [...]byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88}
	if len(buf) >= len(lengthPrefixes) {
		panic("BER length exceeds host int width")
	}
	return append([]byte{lengthPrefixes[len(buf)]}, buf...)
}

// checkedBERCapacity rejects an output length that cannot be represented by
// the host int before any slice allocation. X.690 (02/2021) §8.1.3 encodes
// the length in octets; this check is about the host representation.
func checkedBERCapacity(limit int, parts ...int) (int, error) {
	if limit < 0 {
		return 0, fmt.Errorf("%w: invalid BER output limit", ErrInvalidValue)
	}
	total := 0
	for _, part := range parts {
		if part < 0 || part > limit-total {
			return 0, fmt.Errorf("%w: BER output exceeds host int or configured limit", ErrInvalidValue)
		}
		total += part
	}
	return total, nil
}

// EncodeTLV assembles a complete TLV (Tag-Length-Value).
func EncodeTLV(t tag.Tag, value []byte) ([]byte, error) {
	return encodeTLVWithLimit(t, value, math.MaxInt)
}

func encodeTLVWithLimit(t tag.Tag, value []byte, limit int) ([]byte, error) {
	tagBytes := t.Encode()
	lenBytes := EncodeLength(len(value))
	capacity, err := checkedBERCapacity(limit, len(tagBytes), len(lenBytes), len(value))
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, capacity)
	result = append(result, tagBytes...)
	result = append(result, lenBytes...)
	result = append(result, value...)
	return result, nil
}

// Fixed-size primitive encoders have a compile-time maximum output below 32
// octets, so their checked TLV assembly cannot exceed the host int.
func encodeFixedTLV(t tag.Tag, value []byte) []byte {
	encoded, err := EncodeTLV(t, value)
	if err != nil {
		panic(err)
	}
	return encoded
}

// EncodeBoolean encodes a boolean value per X.690 section 8.2.
func EncodeBoolean(v bool) []byte {
	if v {
		return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}, []byte{0xFF})
	}
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}, []byte{0x00})
}

// EncodeInteger encodes an integer value per X.690 section 8.3.
// Uses two's complement with minimal octets.
func EncodeInteger(v int64) []byte {
	return encodeFixedTLV(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagInteger},
		encodeIntBytes(v),
	)
}

// EncodeUint64 encodes the full nonnegative uint64 range as an ASN.1 INTEGER.
// ITU-T X.690 (02/2021) §8.3 requires a leading zero octet when bit 63 is set.
func EncodeUint64(v uint64) []byte {
	encoded, _ := EncodeBigInt(new(big.Int).SetUint64(v))
	return encoded
}

func encodeIntBytes(v int64) []byte {
	if v == 0 {
		return []byte{0x00}
	}

	// Form the two's-complement bit pattern without a narrowing conversion
	// of a negative integer.
	var uv uint64
	if v >= 0 {
		uv = uint64(v)
	} else {
		uv = ^uint64(-(v + 1))
	}

	var buf [8]byte
	for i := len(buf); i > 0; {
		i--
		buf[i] = byte(uv & 0xFF)
		uv >>= 8
	}

	// Strip leading 0x00 or 0xFF bytes, keeping minimal encoding.
	start := 0
	if v >= 0 {
		for start < 7 {
			if buf[start] != 0 || buf[start+1]&0x80 != 0 {
				break
			}
			start++
		}
	} else {
		for start < 7 {
			if buf[start] != 0xFF || buf[start+1]&0x80 == 0 {
				break
			}
			start++
		}
	}

	return buf[start:]
}

// EncodeBigInt encodes a *big.Int per X.690 section 8.3.
func EncodeBigInt(v *big.Int) ([]byte, error) {
	if v == nil {
		return EncodeInteger(0), nil
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
		for i := len(pb); i > 0; {
			i--
			var val byte
			if pb[i] >= borrow {
				val = pb[i] - borrow
				borrow = 0
			} else {
				val = 0xFF
				borrow = 1
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
func EncodeBitString(bytes []byte, unusedBits int) ([]byte, error) {
	return encodeBitStringWithLimit(bytes, unusedBits, math.MaxInt)
}

// EncodeDERNamedBitString removes trailing zero bits from a named BIT STRING
// before DER encoding, as required by ITU-T X.690 (02/2021) §11.2.2.
func EncodeDERNamedBitString(bytes []byte, bitLength int) ([]byte, error) {
	if err := ValidateDERBitString(bytes, bitLength); err != nil {
		return nil, err
	}
	// The last nonzero octet contains the highest-numbered named bit.
	end := len(bytes)
	for end > 0 {
		if bytes[end-1] != 0 {
			break
		}
		end--
	}
	if end == 0 {
		return EncodeBitString(nil, 0)
	}
	return EncodeBitString(bytes[:end], mathbits.TrailingZeros8(bytes[end-1]))
}

func encodeBitStringWithLimit(bytes []byte, unusedBits, limit int) ([]byte, error) {
	// X.690 (02/2021) §§8.6.2.2–8.6.2.3: the count is 0–7, and an
	// empty BIT STRING has no unused bits.
	if unusedBits < 0 || unusedBits > 7 || len(bytes) == 0 && unusedBits != 0 {
		return nil, fmt.Errorf("%w: invalid BIT STRING unused-bit count", ErrInvalidValue)
	}
	if len(bytes) == 0 {
		return encodeTLVWithLimit(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}, []byte{0x00}, limit)
	}
	capacity, err := checkedBERCapacity(limit, 1, len(bytes))
	if err != nil {
		return nil, err
	}
	value := make([]byte, capacity)
	value[0] = byte(unusedBits)
	copy(value[1:], bytes)
	return encodeTLVWithLimit(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}, value, limit)
}

// EncodeOctetString encodes an octet string per X.690 section 8.7.
func EncodeOctetString(v []byte) ([]byte, error) {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagOctetString}, v)
}

// EncodeNull encodes a NULL value per X.690 section 8.8.
func EncodeNull() []byte {
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagNull}, nil)
}

// EncodeObjectIdentifier encodes an OID per X.690 (02/2021) §8.19.
func EncodeObjectIdentifier(oid []uint64) ([]byte, error) {
	return EncodeObjectIdentifierChecked(oid)
}

// EncodeObjectIdentifierChecked encodes a validated OID per X.690
// (02/2021) section 8.19.4.
func EncodeObjectIdentifierChecked(oid []uint64) ([]byte, error) {
	value, err := EncodeOIDValueChecked(oid)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagObjectID}, value)
}

// EncodeRelativeObjectIdentifierChecked encodes a validated RELATIVE-OID per
// X.690 (02/2021) section 8.20.
func EncodeRelativeObjectIdentifierChecked(oid []uint64) ([]byte, error) {
	value, err := EncodeRelativeOIDValueChecked(oid)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagRelativeOID}, value)
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
	for i := 0; i < len(buf)-1; {
		buf[i] |= 0x80
		i++
	}
	return buf
}

// EncodeEnumerated encodes an enumerated value per X.690 section 8.4.
func EncodeEnumerated(v int64) []byte {
	return encodeFixedTLV(
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
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
}

// EncodeBERReal replays a valid received REAL only when the unchanged value
// cannot be encoded in DER (X.690 (02/2021) §§8.5.7.4, 11.3.1).
func EncodeBERReal(value runtime.Real) ([]byte, error) {
	encoded, err := EncodeReal(value)
	if err == nil {
		return encoded, nil
	}
	contents, ok := value.BERContents()
	if !ok {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
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
		// X.690 (02/2021) §8.5.8: decimal REAL uses an NR3 character form.
		exponent := canonical.Exponent.String()
		if canonical.Exponent.Sign() == 0 {
			exponent = "+0"
		}
		mantissa := canonical.Mantissa.String()
		capacity, err := decimalRealCapacity(len(mantissa), len(exponent))
		if err != nil {
			return nil, err
		}
		contents := make([]byte, 0, capacity)
		contents = append(contents, 0x03)
		contents = append(contents, mantissa...)
		contents = append(contents, '.', 'E')
		contents = append(contents, exponent...)
		return contents, nil
	}

	mantissa := new(big.Int).Set(canonical.Mantissa)
	info := byte(0x80)
	if mantissa.Sign() < 0 {
		info |= 0x40
		mantissa.Abs(mantissa)
	}
	exponent, err := EncodeBigIntValue(canonical.Exponent)
	if err != nil {
		return nil, err
	}
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

func decimalRealCapacity(mantissa, exponent int) (int, error) {
	const overhead = 3 // NR3 identifier, decimal point, and exponent marker.
	if mantissa < 0 || exponent < 0 || mantissa > math.MaxInt-overhead || exponent > math.MaxInt-overhead-mantissa {
		return 0, fmt.Errorf("%w: decimal REAL exceeds host int", ErrInvalidValue)
	}
	return overhead + mantissa + exponent, nil
}

// EncodeUTF8String encodes a UTF8String.
func EncodeUTF8String(v string) ([]byte, error) {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagUTF8String}, []byte(v))
}

// EncodeIA5String encodes an IA5String.
func EncodeIA5String(v string) ([]byte, error) {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagIA5String}, []byte(v))
}

// EncodePrintableString encodes a PrintableString.
func EncodePrintableString(v string) ([]byte, error) {
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagPrintableString}, []byte(v))
}

// EncodeStringTag encodes a character string value under an arbitrary
// UNIVERSAL tag number. Invalid values return nil; generated code uses
// EncodeStringTagChecked so it can report the validation error.
func EncodeStringTag(tagNum int, v string) ([]byte, error) {
	return EncodeStringTagChecked(tagNum, v)
}

// EncodeStringTagChecked applies the fixed-width forms required by X.690
// (02/2021) sections 8.23.7 and 8.23.8 before wrapping the value.
func EncodeStringTagChecked(tagNum int, v string) ([]byte, error) {
	value, err := EncodeStringValueTagChecked(tagNum, v)
	if err != nil {
		return nil, err
	}
	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tagNum}, value)
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
		capacity, err := fixedWidthStringCapacity(utf8.RuneCountInString(v), 2)
		if err != nil {
			return nil, err
		}
		value := make([]byte, 0, capacity)
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
		capacity, err := fixedWidthStringCapacity(utf8.RuneCountInString(v), 4)
		if err != nil {
			return nil, err
		}
		value := make([]byte, 0, capacity)
		for _, r := range v {
			if r < 0 || r > utf8.MaxRune || !utf8.ValidRune(r) {
				return nil, fmt.Errorf("UniversalString character U+%04X is not a Unicode scalar value", r)
			}
			value = binary.BigEndian.AppendUint32(value, uint32(r))
		}
		return value, nil
	default:
		return []byte(v), nil
	}
}

func fixedWidthStringCapacity(octets, width int) (int, error) {
	if octets < 0 || width <= 0 || octets > math.MaxInt/width {
		return 0, fmt.Errorf("%w: fixed-width string exceeds host int", ErrInvalidValue)
	}
	return octets * width, nil
}

// EncodeUTCTime encodes a UTCTime with its lexical form verbatim, as BER
// permits any X.680 (02/2021) §47.3 form (X.690 (02/2021) §8.25). An unset
// value is rejected.
func EncodeUTCTime(value runtime.UTCTime) ([]byte, error) {
	if value.IsZero() {
		return nil, fmt.Errorf("%w: %w", ErrInvalidValue, runtime.ErrTimeNotSet)
	}
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagUTCTime}, []byte(value.String())), nil
}

// EncodeGeneralizedTime encodes a GeneralizedTime with its lexical form
// verbatim, as BER permits any X.680 (02/2021) §46.3 form (X.690 (02/2021)
// §8.25). An unset value is rejected.
func EncodeGeneralizedTime(value runtime.GeneralizedTime) ([]byte, error) {
	if value.IsZero() {
		return nil, fmt.Errorf("%w: %w", ErrInvalidValue, runtime.ErrTimeNotSet)
	}
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagGeneralizedTime}, []byte(value.String())), nil
}

// EncodeUTCTimeDER encodes the X.690 (02/2021) §11.8 form YYMMDDhhmmssZ.
// A value with no such form, or an unset value, is rejected.
func EncodeUTCTimeDER(value runtime.UTCTime) ([]byte, error) {
	canonical, err := value.Canonical()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagUTCTime}, []byte(canonical.String())), nil
}

// EncodeGeneralizedTimeDER encodes the X.690 (02/2021) §11.7 form
// YYYYMMDDhhmmss[.f]Z. A local time of day, a value with no four-digit UTC
// year, or an unset value is rejected.
func EncodeGeneralizedTimeDER(value runtime.GeneralizedTime) ([]byte, error) {
	canonical, err := value.Canonical()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagGeneralizedTime}, []byte(canonical.String())), nil
}

// EncodeSequence encodes a SEQUENCE (constructed) from pre-encoded children.
func EncodeSequence(children []byte) ([]byte, error) {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true},
		children,
	)
}

// EncodeConstructedIndefinite encodes a constructed TLV using BER indefinite length form.
// This produces: tag bytes + 0x80 + children + 0x00 0x00.
func EncodeConstructedIndefinite(t tag.Tag, children []byte) ([]byte, error) {
	return encodeConstructedIndefiniteWithLimit(t, children, math.MaxInt)
}

func encodeConstructedIndefiniteWithLimit(t tag.Tag, children []byte, limit int) ([]byte, error) {
	t.Constructed = true
	tagBytes := t.Encode()
	capacity, err := checkedBERCapacity(limit, len(tagBytes), 1, len(children), 2)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, capacity)
	result = append(result, tagBytes...)
	result = append(result, 0x80) // indefinite length
	result = append(result, children...)
	result = append(result, 0x00, 0x00) // end-of-contents
	return result, nil
}

// EncodeSet encodes a SET (constructed) from pre-encoded children.
// For DER, children should be sorted by tag before calling this.
func EncodeSet(children []byte) ([]byte, error) {
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
	joined, err := joinDERElements(elements)
	if err != nil {
		return nil, err
	}
	return EncodeSet(joined)
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
	joined, err := joinDERElements(elements)
	if err != nil {
		return nil, err
	}
	return EncodeSet(joined)
}

type derElement struct {
	tag     tag.Tag
	encoded []byte
}

func splitDERElements(children []byte) ([]derElement, error) {
	var elements []derElement
	for offset := 0; offset < len(children); {
		decodedTag, total, _, err := DecodeTLV(children[offset:], encodingStructureOption(children[offset:]))
		if err != nil {
			return nil, fmt.Errorf("DER SET element at offset %d: %w", offset, err)
		}
		if total <= 0 || total > len(children)-offset {
			return nil, ErrInvalidLength
		}
		encoded := children[offset : offset+total]
		if err := ValidateDEREncodedElement(encoded); err != nil {
			return nil, fmt.Errorf("DER SET element at offset %d: %w", offset, err)
		}
		elements = append(elements, derElement{tag: decodedTag, encoded: encoded})
		offset += total
	}
	return elements, nil
}

func joinDERElements(elements []derElement) ([]byte, error) {
	length := 0
	for _, element := range elements {
		next, err := checkedBERCapacity(math.MaxInt, length, len(element.encoded))
		if err != nil {
			return nil, err
		}
		length = next
	}
	joined := make([]byte, 0, length)
	for _, element := range elements {
		joined = append(joined, element.encoded...)
	}
	return joined, nil
}

// EncodeExplicitTag wraps encoded content in an explicit context-specific tag.
func EncodeExplicitTag(tagNum int, content []byte) ([]byte, error) {
	return EncodeTLV(
		tag.Tag{Class: tag.ClassContextSpecific, Number: tagNum, Constructed: true},
		content,
	)
}

// EncodeExplicitTagWithClass wraps encoded content in an explicit tag with the given class.
func EncodeExplicitTagWithClass(tagClass tag.Class, tagNum int, content []byte) ([]byte, error) {
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
	_, total, _, err := DecodeTLV(content, encodingStructureOption(content))
	if err != nil {
		return nil, fmt.Errorf("retag implicit value: %w", err)
	}
	if total < 0 || total > len(content) {
		return nil, ErrInvalidLength
	}
	if total != len(content) {
		return nil, fmt.Errorf("%w: implicit value has %d trailing octets", ErrInvalidValue, len(content)-total)
	}
	replacement := tag.Tag{Class: tagClass, Number: tagNum, Constructed: decodedTag.Constructed}.Encode()
	capacity, err := retagCapacity(len(replacement), len(content), tagLength)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, capacity)
	encoded = append(encoded, replacement...)
	encoded = append(encoded, content[tagLength:]...)
	return encoded, nil
}

func retagCapacity(replacement, content, oldTag int) (int, error) {
	if replacement < 0 || content < 0 || oldTag < 0 || oldTag > content || replacement > math.MaxInt-(content-oldTag) {
		return 0, fmt.Errorf("%w: retagged TLV length exceeds host int", ErrInvalidValue)
	}
	return replacement + (content - oldTag), nil
}

// EncodeConstructed encodes a constructed TLV with a custom tag.
func EncodeConstructed(t tag.Tag, children []byte) ([]byte, error) {
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
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}, []byte{rawByte})
}

// EncodeBitStringValue returns the raw value bytes for a bit string.
func EncodeBitStringValue(bytes []byte, unusedBits int) ([]byte, error) {
	return encodeBitStringValueWithLimit(bytes, unusedBits, math.MaxInt)
}

func encodeBitStringValueWithLimit(bytes []byte, unusedBits, limit int) ([]byte, error) {
	// X.690 (02/2021) §§8.6.2.2–8.6.2.3.
	if unusedBits < 0 || unusedBits > 7 || len(bytes) == 0 && unusedBits != 0 {
		return nil, fmt.Errorf("%w: invalid BIT STRING unused-bit count", ErrInvalidValue)
	}
	capacity, err := checkedBERCapacity(limit, 1, len(bytes))
	if err != nil {
		return nil, err
	}
	result := make([]byte, capacity)
	result[0] = byte(unusedBits)
	copy(result[1:], bytes)
	return result, nil
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
func EncodeBigIntValue(v *big.Int) ([]byte, error) {
	full, err := EncodeBigInt(v)
	if err != nil {
		return nil, err
	}
	// EncodeBigInt emits tag + length + contents; the contents start after
	// the 1-octet universal INTEGER tag and its length field.
	_, _, value, err := DecodeTLV(full, encodingStructureOption(full))
	if err != nil {
		return nil, err
	}
	return value, nil
}
