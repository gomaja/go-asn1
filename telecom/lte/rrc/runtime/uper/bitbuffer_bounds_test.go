// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/bitbuffer_bounds_test.go; SHA-256 dc7e736119d67953cefd0f563de21c546dc4914c0a678dc381aec4b989807cb0.
package uper

import (
	"math"
	"testing"
)

func TestBitBufferFromBitsBounds(t *testing.T) {
	for _, tc := range []struct {
		data  []byte
		bits  int
		valid bool
	}{
		{[]byte{0x80}, 1, true},
		{[]byte{0x80}, 0, false},
		{[]byte{0x81}, 1, false},
		{[]byte{0x80}, 9, false},
		{[]byte{0x80}, -1, false},
	} {
		bb, err := NewBitBufferFromBits(tc.data, tc.bits)
		if (err == nil) != tc.valid {
			t.Fatalf("bits %d data %x: err = %v", tc.bits, tc.data, err)
		}
		if err != nil {
			continue
		}
		if got, err := bb.ReadBit(); err != nil || got != 1 {
			t.Fatalf("first bit = %d, %v", got, err)
		}
		if _, err := bb.ReadBit(); err == nil {
			t.Fatal("read beyond declared bit length succeeded")
		}
	}
}

func TestAlignToOctetWriteReturnsWriteBitFailure(t *testing.T) {
	bb := NewBitBuffer()
	bb.bitPos = math.MaxInt
	if err := bb.AlignToOctetWrite(); err == nil {
		t.Fatal("alignment hid the bit-position overflow")
	}
	if bb.bitPos != math.MaxInt || len(bb.data) != 0 {
		t.Fatalf("failed alignment changed buffer: position=%d bytes=%d", bb.bitPos, len(bb.data))
	}
}
