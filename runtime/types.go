// Package runtime provides common ASN.1 runtime types used by generated code.
package runtime

import (
	"encoding/hex"
	"fmt"
)

// BitString represents an ASN.1 BIT STRING value.
type BitString struct {
	Bytes      []byte
	BitLength  int
}

// Has returns true if the bit at the given position is set.
func (bs BitString) Has(bit int) bool {
	if bit < 0 || bit >= bs.BitLength {
		return false
	}
	byteIndex := bit / 8
	bitIndex := 7 - (bit % 8)
	return bs.Bytes[byteIndex]&(1<<uint(bitIndex)) != 0
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
		return fmt.Errorf("RawValue: expected hex string, got %s", data)
	}
	b, err := hex.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return fmt.Errorf("RawValue: invalid hex: %w", err)
	}
	rv.Bytes = b
	return nil
}
