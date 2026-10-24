// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/bitbuffer_arithmetic_test.go; SHA-256 019e17521543d949c217158f229c88baa5322ecb7fa3386761a8dd6b0bf8a945.
package uper

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

func TestBitBufferRejectsUnrepresentableBitCount386(t *testing.T) {
	if strconv.IntSize != 32 {
		t.Skip("requires 32-bit int")
	}
	wire := make([]byte, math.MaxInt/8+1)
	input := NewBitBufferFromBytes(wire)
	if _, err := input.ReadBit(); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReadBit after oversized input error = %v, want ErrInvalidValue", err)
	}
	if _, err := input.ReadBits(0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReadBits after oversized input error = %v, want ErrInvalidValue", err)
	}
	if _, err := input.ReadBytes(0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReadBytes after oversized input error = %v, want ErrInvalidValue", err)
	}
	if _, err := input.ReadBitsToBytes(0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReadBitsToBytes after oversized input error = %v, want ErrInvalidValue", err)
	}
	if _, err := CaptureFinalPadding(input); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("CaptureFinalPadding after oversized input error = %v, want ErrInvalidValue", err)
	}
	bounded, err := NewBitBufferFromBits(wire, math.MaxInt)
	if err != nil || bounded.BitsRemaining() != math.MaxInt {
		t.Fatalf("NewBitBufferFromBits rejected maximum representable bit length: %v", err)
	}
	// X.691 (02/2021) §§11.1.1(b), 11.1.3.2: the exact unpadded
	// bit length can fit even when the backing octets' padded length does not.
	if err := input.SetReadBitLength(math.MaxInt); err != nil || input.BitsRemaining() != math.MaxInt {
		t.Fatalf("SetReadBitLength rejected maximum representable bit length: %v", err)
	}
	for _, bits := range []int{math.MaxInt - 6, math.MaxInt} {
		bounded, err := NewBitBufferFromBits(wire, bits)
		if err != nil || bounded.BitsRemaining() != bits {
			t.Fatalf("NewBitBufferFromBits(%d): %v", bits, err)
		}
		bounded.bitPos = bits - 1
		if _, err := bounded.ReadBit(); err != nil || bounded.BitsRemaining() != 0 {
			t.Fatalf("last declared bit (%d): %v", bits, err)
		}
		if _, err := bounded.ReadBit(); !errors.Is(err, ErrTruncated) {
			t.Fatalf("read past declared length (%d): %v", bits, err)
		}
	}
	wire[len(wire)-1] = 1
	if _, err := NewBitBufferFromBits(wire, math.MaxInt); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nonzero unused bit accepted: %v", err)
	}
	wire[len(wire)-1] = 0
	if _, err := NewBitBufferFromBits(wire, math.MaxInt-7); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("excess backing octet accepted: %v", err)
	}
}

func TestBitBufferRejectsWritePositionOverflow(t *testing.T) {
	bb := &BitBuffer{bitPos: math.MaxInt}
	if err := bb.WriteBit(0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("WriteBit at MaxInt error = %v, want ErrInvalidValue", err)
	}
}
