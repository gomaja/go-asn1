// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/hardening_test.go; SHA-256 bb2e336ce18c079e65911df9d7bd065066fc48d48ce4de362f5d228fe26ecdb1.
package uper

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestAddNonNegativeOffsetInt64Boundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lb     int64
		offset uint64
		want   int64
	}{
		{name: "minimum unchanged", lb: math.MinInt64, want: math.MinInt64},
		{name: "minimum plus full width", lb: math.MinInt64, offset: ^uint64(0), want: math.MaxInt64},
		{name: "negative crosses zero", lb: -10, offset: 10, want: 0},
		{name: "negative reaches maximum", lb: -10, offset: uint64(math.MaxInt64) + 10, want: math.MaxInt64},
		{name: "zero reaches maximum", offset: math.MaxInt64, want: math.MaxInt64},
		{name: "maximum unchanged", lb: math.MaxInt64, want: math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := addNonNegativeOffset(tc.lb, tc.offset)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("addNonNegativeOffset(%d, %d) = %d, want %d", tc.lb, tc.offset, got, tc.want)
			}
		})
	}
}

func TestAddNonNegativeOffsetRejectsOverflow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lb     int64
		offset uint64
	}{
		{name: "negative lower bound", lb: -10, offset: uint64(math.MaxInt64) + 11},
		{name: "zero lower bound", offset: uint64(math.MaxInt64) + 1},
		{name: "maximum lower bound", lb: math.MaxInt64, offset: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := addNonNegativeOffset(tc.lb, tc.offset); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("overflow error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

func TestBitBufferRejectsImpossibleReadsBeforeAllocation(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0})
	if _, err := bb.ReadBytes(math.MaxInt); !errors.Is(err, ErrTruncated) {
		t.Fatalf("ReadBytes error = %v, want ErrTruncated", err)
	}
	if _, err := bb.ReadBitsToBytes(math.MaxInt); !errors.Is(err, ErrTruncated) {
		t.Fatalf("ReadBitsToBytes error = %v, want ErrTruncated", err)
	}
}

func TestBitBufferRejectsNegativeCursor(t *testing.T) {
	writer := NewBitBuffer()
	writer.bitPos = -1
	if err := writer.WriteBit(1); err == nil || !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "negative PER bit position") {
		t.Fatalf("WriteBit with negative cursor = %v, want ErrInvalidValue", err)
	}
	if writer.bitPos != -1 || len(writer.data) != 0 {
		t.Fatalf("WriteBit mutated invalid buffer: cursor=%d data=%x", writer.bitPos, writer.data)
	}

	reader := NewBitBufferFromBytes([]byte{0x80})
	reader.bitPos = -1
	if _, err := reader.ReadBit(); err == nil || !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "negative PER bit position") {
		t.Fatalf("ReadBit with negative cursor = %v, want ErrInvalidValue", err)
	}
	if reader.bitPos != -1 {
		t.Fatalf("ReadBit advanced invalid cursor to %d", reader.bitPos)
	}
}
