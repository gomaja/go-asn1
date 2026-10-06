// Package runtime provides common ASN.1 runtime types used by generated code.
package runtime

import (
	"encoding/hex"
	"fmt"
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

// ObjectIdentifier represents an ASN.1 OBJECT IDENTIFIER value.
type ObjectIdentifier []uint64

// Equal returns true if two OIDs are equal.
func (oid ObjectIdentifier) Equal(other ObjectIdentifier) bool {
	if len(oid) != len(other) {
		return false
	}
	for i := range oid {
		if oid[i] != other[i] {
			return false
		}
	}
	return true
}

// RawValue represents an unparsed ASN.1 value (used for ANY/OPEN TYPE).
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
	rv.Bytes = b
	return nil
}
