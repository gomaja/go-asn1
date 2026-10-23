// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/fragment_test.go; SHA-256 b071f198c092cce47381204da72b9c938796c2930b9e19a418173f1f7422d0ae.
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

// X.691 (02/2021) 11.9.3.8: length fragments include a final determinant.
// The fixed determinants independently test the callback offsets and lengths.
func TestDecodeLengthFragments(t *testing.T) {
	wire := append([]byte{0xc4}, make([]byte, 4*perFragmentUnit)...)
	wire = append(wire, 2, 0xab, 0xcd)
	bb := NewBitBufferFromBytes(wire)
	var fragments [][2]int64
	total, err := DecodeLengthFragments(bb, false, func(offset, length int64) error {
		fragments = append(fragments, [2]int64{offset, length})
		_, err := bb.ReadBytes(int(length))
		return err
	})
	if err != nil || total != 4*perFragmentUnit+2 || len(fragments) != 2 || fragments[0] != [2]int64{0, 4 * perFragmentUnit} || fragments[1] != [2]int64{4 * perFragmentUnit, 2} || bb.BitsRemaining() != 0 {
		t.Fatalf("fragments=%v total=%d remaining=%d err=%v", fragments, total, bb.BitsRemaining(), err)
	}
	sentinel := errors.New("fragment rejected")
	if _, err := DecodeLengthFragments(NewBitBufferFromBytes([]byte{0}), false, func(int64, int64) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback error lost: %v", err)
	}
	if _, err := DecodeLengthFragments(NewBitBufferFromBytes(nil), false, func(int64, int64) error { return nil }); !errors.Is(err, ErrTruncated) {
		t.Fatalf("missing length accepted: %v", err)
	}
	if _, err := DecodeLengthFragments(NewBitBufferFromBytes([]byte{0}), false, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil callback accepted: %v", err)
	}
}
