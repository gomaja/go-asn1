package ber

import "testing"

func TestUnusedBitCount(t *testing.T) {
	for _, tc := range []struct{ length, unused int }{
		{0, 0}, {1, 7}, {7, 1}, {8, 0}, {9, 7}, {15, 1}, {16, 0},
	} {
		if got := UnusedBitCount(tc.length); got != tc.unused {
			t.Errorf("UnusedBitCount(%d) = %d, want %d", tc.length, got, tc.unused)
		}
	}
}
