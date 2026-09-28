package per

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
}

func TestBitBufferRejectsWritePositionOverflow(t *testing.T) {
	bb := &BitBuffer{bitPos: math.MaxInt}
	if err := bb.WriteBit(0); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("WriteBit at MaxInt error = %v, want ErrInvalidValue", err)
	}
}
