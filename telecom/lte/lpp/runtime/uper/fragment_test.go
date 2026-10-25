// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/fragment_test.go; SHA-256 664b032e2da97482fb24e5d706f9f9359a4bac3037d132fb6f3eafc0f954c29b.
package uper

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestBitLengthValidationDoesNotOverflow(t *testing.T) {
	bb := NewBitBuffer()
	if err := bb.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), bb.Bytes()...)
	beforeBits := bb.BitsWritten()
	if err := encodeLengthDelimitedBits(bb, nil, math.MaxInt, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("encode error = %v, want ErrInvalidValue", err)
	}
	if !bytes.Equal(bb.Bytes(), before) || bb.BitsWritten() != beforeBits {
		t.Fatal("encoder mutated the buffer for an impossible source length")
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("WriteBitsFromBytes panicked: %v", recovered)
		}
	}()
	if err := bb.WriteBitsFromBytes(nil, math.MaxInt); err == nil {
		t.Fatal("WriteBitsFromBytes accepted an impossible source length")
	}
}

func TestFragmentedOctetStringWireDeterminants(t *testing.T) {
	for _, length := range []int{perFragmentUnit, 4 * perFragmentUnit, 4*perFragmentUnit + 1, 5 * perFragmentUnit} {
		bb := NewBitBuffer()
		if err := EncodeOctetString(bb, make([]byte, length), 0, 0, false); err != nil {
			t.Fatal(err)
		}
		wire := bb.Bytes()
		firstMultiplier := length / perFragmentUnit
		if firstMultiplier > 4 {
			firstMultiplier = 4
		}
		if wire[0] != byte(0xc0|firstMultiplier) {
			t.Fatalf("length %d first determinant = %02x, want %02x", length, wire[0], 0xc0|firstMultiplier)
		}
		firstEnd := 1 + firstMultiplier*perFragmentUnit
		if length == firstMultiplier*perFragmentUnit {
			if len(wire) <= firstEnd {
				t.Fatalf("length %d omitted terminal determinant", length)
			}
			if wire[firstEnd] != 0 {
				t.Fatalf("length %d terminal determinant = %02x, want 00", length, wire[firstEnd])
			}
		}
	}
}

func TestFragmentedLengthRejectsMalformedDeterminants(t *testing.T) {
	fragment := make([]byte, perFragmentUnit)
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{name: "non-minimal long form", wire: []byte{0x80, 0x7f}},
		{name: "zero multiplier", wire: []byte{0xc0}},
		{name: "multiplier above four", wire: []byte{0xc5}},
		{name: "truncated fragment", wire: []byte{0xc1}},
		{name: "missing terminal determinant", wire: append([]byte{0xc1}, fragment...)},
		{name: "non-maximal prior fragment", wire: append(append(append([]byte{0xc1}, fragment...), 0xc1), fragment...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeOctetString(NewBitBufferFromBytes(tc.wire), 0, 0, false)
			if err == nil {
				t.Fatal("malformed determinant accepted")
			}
			if strings.Contains(tc.name, "truncated") || strings.Contains(tc.name, "missing terminal") {
				if !errors.Is(err, ErrTruncated) {
					t.Fatalf("error = %v, want ErrTruncated", err)
				}
			} else if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

// X.691 (02/2021) 30.5.2: B2 = 8 bits per character.

func TestFragmentedCollectionCallbacksInterleavePayload(t *testing.T) {
	const count = perFragmentUnit + 1
	for _, aligned := range []bool{false} {
		bb := NewBitBuffer()
		if err := EncodeCollection(bb, count, SizeConstraint{}, aligned, func(offset, length int64) error {
			for index := int64(0); index < length; index++ {
				if err := EncodeBoolean(bb, (offset+index)%2 != 0); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		wire := bb.Bytes()
		if wire[0] != 0xc1 {
			t.Fatalf("aligned=%v first determinant = %02x, want c1", aligned, wire[0])
		}
		terminalOffset := 1 + perFragmentUnit/8
		if wire[terminalOffset] != 1 {
			t.Fatalf("aligned=%v terminal determinant = %02x, want 01", aligned, wire[terminalOffset])
		}

		reader := NewBitBufferFromBytes(wire)
		var decoded int64
		total, err := DecodeCollection(reader, SizeConstraint{}, aligned, func(offset, length int64) error {
			if offset != decoded {
				return errors.New("non-contiguous collection callback")
			}
			for index := int64(0); index < length; index++ {
				value, err := DecodeBoolean(reader)
				if err != nil {
					return err
				}
				if value != ((offset+index)%2 != 0) {
					return errors.New("collection element mismatch")
				}
			}
			decoded += length
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if total != count || decoded != count {
			t.Fatalf("aligned=%v decoded = %d/%d, want %d", aligned, total, decoded, count)
		}
	}
}
