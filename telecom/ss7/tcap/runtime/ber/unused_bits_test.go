// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/unused_bits_test.go; SHA-256 72c3222eedf8117c588ef5c2aa2ffff63ededcd5ed701491d14b8918856e7350.
package ber

import (
	"testing"
)

func TestUnusedBitCount(t *testing.T) {
	for _, tc := range []struct{ length, unused int }{
		{0, 0}, {1, 7}, {7, 1}, {8, 0}, {9, 7}, {15, 1}, {16, 0},
	} {
		if got := UnusedBitCount(tc.length); got != tc.unused {
			t.Errorf("UnusedBitCount(%d) = %d, want %d", tc.length, got, tc.unused)
		}
	}
}
