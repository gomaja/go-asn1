// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/normally_small_length_test.go; SHA-256 53cb0f629c484bbebf1f2984687add194c0bcaf814242f2b8ce19c4ef31a9445.
package uper

import (
	"bytes"
	"testing"
)

// ITU-T X.691 (02/2021) 11.9.3.4 and 19.8: a 70-bit extension
// bitmap starts with the normally small length 70, not whole number 69.
func TestExtensionBitmapNormallySmallLengthSeventy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix []byte
		decode func(*BitBuffer) (int64, []bool, error)
		encode func(*BitBuffer, int64) error
	}{
		{"UPER", []byte{0xa3, 0x00}, DecodeExtensionBitmap, EncodeNormallySmallLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := append(append([]byte(nil), tc.prefix...), make([]byte, 9)...)
			if tc.name == "UPER" {
				input = input[:10]
			}
			count, present, err := tc.decode(NewBitBufferFromBytes(input))
			if err != nil || count != 69 || len(present) != 70 {
				t.Fatalf("bitmap count=%d, len=%d, err=%v", count, len(present), err)
			}
			for i, bit := range present {
				if bit {
					t.Fatalf("bitmap bit %d set", i)
				}
			}
			bb := NewBitBuffer()
			if err := tc.encode(bb, 70); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.Bytes(), tc.prefix) {
				t.Fatalf("length prefix = %x, want %x", bb.Bytes(), tc.prefix)
			}
		})
	}
}
