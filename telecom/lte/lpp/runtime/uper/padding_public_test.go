// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/padding_public_test.go; SHA-256 e23406e9bea68fef06448fc2fdb94dab1a8ce48d9403e34f0ab9d237f3364664.
package uper_test

import (
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/lpp/runtime/uper"
)

func TestCompletePaddingObservedBits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  byte
		value uint8
		count uint8
		zero  bool
	}{
		{"canonical", 0x00, 0, 0, true}, // zero padding is not retained
		{"nonzero", 0x05, 5, 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := uper.NewBitBufferFromBytes([]byte{tc.wire})
			if _, err := bb.ReadBits(3); err != nil {
				t.Fatal(err)
			}
			padding, err := uper.CaptureFinalPadding(bb)
			if err != nil {
				t.Fatal(err)
			}
			value, count := padding.Bits()
			if value != tc.value || count != tc.count || padding.IsZero() != tc.zero {
				t.Fatalf("padding = (%d, %d, %v), want (%d, %d, %v)", value, count, padding.IsZero(), tc.value, tc.count, tc.zero)
			}
		})
	}
}
