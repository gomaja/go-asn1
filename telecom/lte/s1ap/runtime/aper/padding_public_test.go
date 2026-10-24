// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/padding_public_test.go; SHA-256 bda4995592f8d8894a753bfee2337de905f3792cd11ee62a12f8ff5b728cfc00.
package aper_test

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
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
			if !tc.zero {
				if !errors.Is(err, aper.ErrSyntax) {
					t.Fatalf("nonzero padding: %v", err)
				}
				return
			}
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
