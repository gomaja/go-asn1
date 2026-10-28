// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/constructed_bit_string_test.go; SHA-256 84d7a67f000709499ab92636236c783f941b171452919946cf650be6b32a28b2.
package ber

import (
	"bytes"
	"testing"
)

func TestDecodeImplicitBitStringValuePreservesConstructedForm(t *testing.T) {
	children := append(mustEncode(t)(EncodeBitString([]byte{0xaa}, 0)), mustEncode(t)(EncodeBitString([]byte{0xb0}, 4))...)
	got, unused, err := DecodeImplicitBitStringValue(true, children)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xaa, 0xb0}) || unused != 4 {
		t.Fatalf("constructed value = %x/%d, want aab0/4", got, unused)
	}

	got, unused, err = DecodeImplicitBitStringValue(false, []byte{4, 0xb0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xb0}) || unused != 4 {
		t.Fatalf("primitive value = %x/%d, want b0/4", got, unused)
	}
}
