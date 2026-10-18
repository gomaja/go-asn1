// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/named_bitstring_test.go; SHA-256 93f5176a9a49b06d32151364a5c7b7fbf778ec3c70772a65be2b02e91af667e3.
package ber

import (
	"bytes"
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

func TestEncodeDERNamedBitStringNormalizesPadding(t *testing.T) {
	input := []byte{0xa1}
	output, err := EncodeDERNamedBitString(input, 3)
	if err != nil || !bytes.Equal(output, []byte{3, 2, 5, 0xa0}) || input[0] != 0xa1 {
		t.Fatalf("normalized output=%x input=%x: %v", output, input, err)
	}
}
