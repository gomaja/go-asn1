// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/types.go; SHA-256 11b3543292920e30c16309da1daf454d936cca520eb02be62ac40b239192c993.
// Package runtime provides common ASN.1 runtime types used by generated code.
package runtime

import (
	"encoding/hex"
	"fmt"
	"math"
)

// BitString represents an ASN.1 BIT STRING value.
type BitString struct {
	Bytes     []byte
	BitLength int
}

// Has returns true if the bit at the given position is set.
func (bs BitString) Has(bit int) bool {
	if bit < 0 || bit >= bs.BitLength {
		return false
	}
	byteIndex := bit / 8
	if byteIndex >= len(bs.Bytes) {
		return false
	}
	bitIndex := 7 - (bit % 8)
	if bitIndex < 0 || bitIndex > 7 {
		return false
	}
	return bs.Bytes[byteIndex]&(1<<uint(bitIndex)) != 0
}

// EqualBits reports whether bs holds the bitLength bits of bits, leading bit
// first in the most significant bit of the first octet. With namedBits, values
// that differ only in trailing zero bits are equal: X.680 (02/2021) 22.7 lets
// encoding rules add and remove those bits for a type with a NamedBitList.
// A BitString whose Bytes cannot hold BitLength bits equals nothing.
func (bs BitString) EqualBits(bits string, bitLength int, namedBits bool) bool {
	left, right := bs.BitLength, bitLength
	if !holdsBits(bs.Bytes, left) || !holdsBits(bits, right) {
		return false
	}
	if namedBits {
		left, right = significantBits(bs.Bytes, left), significantBits(bits, right)
	}
	if left != right {
		return false
	}
	for bit := range left {
		if bs.Bytes[bit/8]&bitMasks[bit%8] != bits[bit/8]&bitMasks[bit%8] {
			return false
		}
	}
	return true
}

var bitMasks = [8]byte{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}

// holdsBits reports whether octets hold length bits.
func holdsBits[T ~string | ~[]byte](octets T, length int) bool {
	return length >= 0 && length/8 <= len(octets) && (length%8 == 0 || length/8 < len(octets))
}

// significantBits returns length without the trailing zero bits of the
// length bits held in octets.
func significantBits[T ~string | ~[]byte](octets T, length int) int {
	for length > 0 {
		last := length - 1
		if octets[last/8]&bitMasks[last%8] != 0 {
			break
		}
		length = last
	}
	return length
}

// ObjectIdentifier holds canonical X.690 (02/2021) §8.19 contents octets.
// Its zero value is absent/invalid; valid values are immutable and comparable.
// Both == and Equal compare the ASN.1 value, and values can be map keys.
type ObjectIdentifier struct{ enc string }

// RelativeObjectIdentifier holds canonical X.690 (02/2021) §8.20 contents.
// Its zero value is absent/invalid; valid values are immutable and comparable.
type RelativeObjectIdentifier struct{ enc string }

// RawValue represents an unparsed ASN.1 value (used for ANY/OPEN TYPE).
// WithoutBERReplay and DER require an opaque element to pass generic DER checks.
// Those checks cannot certify an unknown IMPLICIT type, foreign DEFAULT or
// schema-specific SET ordering; such rules require a typed binding.
// Bytes contains the complete TLV and is the sole input to encoding. Class,
// Tag and Constructed must match that identifier. Encoding rejects inconsistent
// metadata instead of changing the bytes to match it.
type RawValue struct {
	Class       int    `json:"-"`
	Tag         int    `json:"-"`
	Constructed bool   `json:"-"`
	Bytes       []byte `json:"-"`
}

// MarshalJSON encodes RawValue as a hex string for readability in protocol analysis.
func (rv RawValue) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(rv.Bytes) + `"`), nil
}

// UnmarshalJSON decodes a hex string back into RawValue.Bytes.
func (rv *RawValue) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("RawValue: expected hex string, got %q", data)
	}
	b, err := hex.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return fmt.Errorf("RawValue: invalid hex: %w", err)
	}
	next := RawValue{Bytes: b}
	if len(b) != 0 {
		class, number, constructed, err := rawJSONIdentifier(b)
		if err != nil {
			return err
		}
		next.Class, next.Tag, next.Constructed = class, number, constructed
	}
	*rv = next
	return nil
}

// X.690 (02/2021) §§8.1.2.1, 8.1.2.4–8.1.2.5 and Erratum 1
// (09/2021, Figure 4). JSON retains a complete identifier without importing
// the BER package back into its runtime types. Encoders check the whole TLV.
func rawJSONIdentifier(data []byte) (int, int, bool, error) {
	if len(data) == 0 {
		return 0, 0, false, fmt.Errorf("RawValue: truncated identifier")
	}
	class, number, constructed := int(data[0]>>6), int(data[0]&31), data[0]&32 != 0
	if number < 31 {
		return class, number, constructed, nil
	}
	number = 0
	for offset := 1; offset < len(data); offset++ {
		group := int(data[offset] & 127)
		if offset == 1 && group == 0 || number > math.MaxInt>>7 || number == math.MaxInt>>7 && group > math.MaxInt&127 {
			return 0, 0, false, fmt.Errorf("RawValue: nonminimal or overflowing identifier")
		}
		number = (number << 7) | group
		if data[offset]&128 == 0 {
			if number < 31 {
				return 0, 0, false, fmt.Errorf("RawValue: high-tag form for tag number %d", number)
			}
			return class, number, constructed, nil
		}
	}
	return 0, 0, false, fmt.Errorf("RawValue: truncated identifier")
}
