// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/padding_public_test.go; SHA-256 10e33ab4d2dd8e707f1ed50c9eba3339c88bd5b125a8bd70700727c54eaef788.
package uper_test

import (
	"testing"

	"github.com/gomaja/go-asn1/telecom/umts/rrc/runtime/uper"
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
