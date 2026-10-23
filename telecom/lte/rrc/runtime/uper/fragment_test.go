// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/fragment_test.go; SHA-256 8c8ae41c3af05dae4120d84f1c315efaf137e88dbe48ded4be7498d88e200f8b.
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
