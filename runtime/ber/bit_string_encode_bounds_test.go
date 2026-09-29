package ber

import "testing"

func TestEncodeBitStringRejectsInvalidUnusedCount(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bytes  []byte
		unused int
	}{
		{"negative", []byte{0}, -1},
		{"above_seven", []byte{0}, 8},
		{"wrapped_byte", []byte{0}, 256},
		{"empty_with_unused", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := EncodeBitString(tc.bytes, tc.unused); err == nil {
				t.Fatalf("EncodeBitString(%x, %d) = %x; want error", tc.bytes, tc.unused, got)
			}
			if got, err := EncodeBitStringValue(tc.bytes, tc.unused); err == nil {
				t.Fatalf("EncodeBitStringValue(%x, %d) = %x; want error", tc.bytes, tc.unused, got)
			}
		})
	}
}
