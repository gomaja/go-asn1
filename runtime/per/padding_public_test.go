package per_test

import (
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
)

func TestCompletePaddingObservedBits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  byte
		value uint8
		count uint8
		zero  bool
	}{
		{"canonical", 0x00, 0, 5, true},
		{"nonzero", 0x05, 5, 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := per.NewBitBufferFromBytes([]byte{tc.wire})
			if _, err := bb.ReadBits(3); err != nil {
				t.Fatal(err)
			}
			padding, err := per.CaptureFinalPadding(bb)
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
