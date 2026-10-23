// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/padding_public_test.go; SHA-256 fb01112433f83f9badd05776ad6aedd0dd35a5a07eb872912baf94de4721c640.
package aper_test

import (
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
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
			bb := aper.NewBitBufferFromBytes([]byte{tc.wire})
			if _, err := bb.ReadBits(3); err != nil {
				t.Fatal(err)
			}
			padding, err := aper.CaptureFinalPadding(bb)
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
