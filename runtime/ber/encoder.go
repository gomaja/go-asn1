package ber

import (
	"math"
	"math/big"
	"time"

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

// EncodeObjectIdentifier encodes an OID per X.690 section 8.19.
func EncodeObjectIdentifier(oid []uint64) []byte {
	if len(oid) < 2 {
		return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagObjectID}, nil)
	}

	// First two components combined: val = oid[0]*40 + oid[1].
	first := oid[0]*40 + oid[1]
	var value []byte
	value = append(value, encodeBase128(first)...)

	for _, arc := range oid[2:] {
		value = append(value, encodeBase128(arc)...)
	}

	return EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagObjectID}, value)
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

// EncodeReal encodes a REAL value per X.690 section 8.5.
func EncodeReal(v float64) []byte {
	t := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}

	if v == 0 {
		if math.Signbit(v) {
			// Negative zero: X.690 §8.5.3 — encode as 0x43.
			return EncodeTLV(t, []byte{0x43})
		}
		return EncodeTLV(t, nil)
	}
	if math.IsInf(v, 1) {
		return EncodeTLV(t, []byte{0x40})
	}
	if math.IsInf(v, -1) {
		return EncodeTLV(t, []byte{0x41})
	}
	if math.IsNaN(v) {
		return EncodeTLV(t, []byte{0x42})
	}

	// Binary encoding: info octet + exponent + mantissa.
	bits := math.Float64bits(v)
	sign := (bits >> 63) & 1
	rawExp := (bits >> 52) & 0x7FF
	mantissa := bits & 0x000FFFFFFFFFFFFF
	var exp int64
	if rawExp == 0 {
		// Subnormal: exponent is 1 - bias - 52 = -1074, no implicit bit.
		exp = 1 - 1023 - 52
	} else {
		// Normal: restore implicit 1 bit.
		exp = int64(rawExp) - 1023 - 52
		mantissa |= 0x0010000000000000
	}

	// Remove trailing zeros from mantissa.
	for mantissa > 0 && mantissa&1 == 0 {
		mantissa >>= 1
		exp++
	}

	// Encode mantissa bytes (unsigned, big-endian).
	var mBytes []byte
	m := mantissa
	for m > 0 {
		mBytes = append([]byte{byte(m & 0xFF)}, mBytes...)
		m >>= 8
	}
	if len(mBytes) == 0 {
		mBytes = []byte{0}
	}

	// Encode exponent bytes (signed, two's complement).
	eBytes := encodeIntBytes(exp)

	// Info octet: 1SBBFFEE
	// S=sign, BB=base(00=2), FF=scale(00), EE=exponent length.
	info := byte(0x80)
	if sign == 1 {
		info |= 0x40
	}
	switch len(eBytes) {
	case 1:
		// EE = 00
	case 2:
		info |= 0x01
	case 3:
		info |= 0x02
	default:
		info |= 0x03
	}

	var value []byte
	value = append(value, info)
	if info&0x03 == 0x03 {
		value = append(value, byte(len(eBytes)))
	}
	value = append(value, eBytes...)
	value = append(value, mBytes...)

	return EncodeTLV(t, value)
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

// EncodeImplicitTag re-tags encoded content with an implicit context-specific tag.
// It replaces the outermost tag but keeps the original constructed flag.
func EncodeImplicitTag(tagNum int, constructed bool, content []byte) []byte {
	// Parse existing TLV to get the value.
	if len(content) == 0 {
		return nil
	}
	_, _, valueBytes, err := DecodeTLV(content)
	if err != nil {
		return nil
	}
	return EncodeTLV(
		tag.Tag{Class: tag.ClassContextSpecific, Number: tagNum, Constructed: constructed},
		valueBytes,
	)
}

// EncodeImplicitTagWithClass re-tags encoded content with an implicit tag of the given class.
func EncodeImplicitTagWithClass(tagClass tag.Class, tagNum int, constructed bool, content []byte) []byte {
	if len(content) == 0 {
		return nil
	}
	_, _, valueBytes, err := DecodeTLV(content)
	if err != nil {
		return nil
	}
	return EncodeTLV(
		tag.Tag{Class: tagClass, Number: tagNum, Constructed: constructed},
		valueBytes,
	)
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

// EncodeOIDValue returns the raw value bytes for an OID.
func EncodeOIDValue(oid []uint64) []byte {
	if len(oid) < 2 {
		return nil
	}
	var buf []byte
	first := oid[0]*40 + oid[1]
	buf = append(buf, encodeBase128(first)...)
	for _, arc := range oid[2:] {
		buf = append(buf, encodeBase128(arc)...)
	}
	return buf
}

// EncodeStringValue returns the raw value bytes for a string.
func EncodeStringValue(s string) []byte {
	return []byte(s)
}
