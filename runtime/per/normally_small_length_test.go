package per

import (
	"bytes"
	"errors"
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
		{"APER", []byte{0x80, 0x46}, DecodeExtensionBitmapAligned, EncodeNormallySmallLengthAligned},
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

func TestFragmentedExtensionBitmapLengthHasTypedError(t *testing.T) {
	for _, test := range []struct {
		name   string
		encode func(*BitBuffer, int64) error
		decode func(*BitBuffer) (int64, []bool, error)
	}{
		{"UPER", EncodeNormallySmallLength, DecodeExtensionBitmap},
		{"APER", EncodeNormallySmallLengthAligned, DecodeExtensionBitmapAligned},
	} {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := test.encode(bb, 16384); !errors.Is(err, ErrUnsupportedFragmentedNormallySmallLength) {
				t.Fatalf("encode error = %v", err)
			}
			if bb.BitsWritten() != 0 {
				t.Fatalf("encode wrote %d bits before rejecting", bb.BitsWritten())
			}
			bb = NewBitBufferFromBytes([]byte{0xe0, 0x80})
			if test.name == "APER" {
				bb = NewBitBufferFromBytes([]byte{0x80, 0xc1})
			}
			if _, _, err := test.decode(bb); !errors.Is(err, ErrUnsupportedFragmentedNormallySmallLength) {
				t.Fatalf("decode error = %v", err)
			}
		})
	}
}
