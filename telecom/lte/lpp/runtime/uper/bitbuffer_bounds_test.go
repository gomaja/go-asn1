// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/bitbuffer_bounds_test.go; SHA-256 cc21bf58e5fc1889ebcad7c34fd2a8f29219bafc184908de92fbe9781ce12ae3.
package uper

import (
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
