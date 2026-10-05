package ber

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeDERNamedBitStringRemovesTrailingZeroBits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		contents  []byte
		bitLength int
		want      []byte
	}{
		{"short", []byte{0xa0}, 3, []byte{0x03, 0x02, 0x05, 0xa0}},
		{"padded", []byte{0xa0, 0x00}, 16, []byte{0x03, 0x02, 0x05, 0xa0}},
		{"empty", nil, 0, []byte{0x03, 0x01, 0x00}},
		{"all zero", []byte{0x00}, 8, []byte{0x03, 0x01, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeDERNamedBitString(tc.contents, tc.bitLength)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("DER = %x, %v; want %x", got, err, tc.want)
			}
		})
	}
}

func TestEncodeDERNamedBitStringRejectsNonzeroPadding(t *testing.T) {
	if _, err := EncodeDERNamedBitString([]byte{0xa1}, 3); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("padding error = %v, want %v", err, ErrInvalidValue)
	}
}
