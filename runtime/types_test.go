package runtime

import (
	"math"
	"testing"
)

func TestBitStringHasBounds(t *testing.T) {
	bits := BitString{Bytes: []byte{0x81, 0x40}, BitLength: 16}
	for _, test := range []struct {
		bit  int
		want bool
	}{
		{-1, false},
		{0, true},
		{1, false},
		{7, true},
		{8, false},
		{9, true},
		{15, false},
		{16, false},
		{math.MaxInt, false},
	} {
		if got := bits.Has(test.bit); got != test.want {
			t.Errorf("Has(%d) = %t; want %t", test.bit, got, test.want)
		}
	}
	short := BitString{Bytes: []byte{0x80}, BitLength: math.MaxInt}
	if short.Has(8) || !short.Has(0) {
		t.Fatal("Has crossed the available byte boundary")
	}
}
