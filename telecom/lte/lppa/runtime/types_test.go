// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/types_test.go; SHA-256 90c22ea863100a23aa9facc890c2fb909f535e8eeff6dc293dfd468b4e311916.
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

func TestBitStringEqualBits(t *testing.T) {
	for _, test := range []struct {
		name      string
		value     BitString
		bits      string
		length    int
		namedBits bool
		want      bool
	}{
		{"same", BitString{Bytes: []byte{0xa0}, BitLength: 3}, "\xa0", 3, false, true},
		{"unused bits ignored", BitString{Bytes: []byte{0xbf}, BitLength: 3}, "\xa0", 3, false, true},
		{"longer", BitString{Bytes: []byte{0xa0}, BitLength: 4}, "\xa0", 3, false, false},
		{"other bit", BitString{Bytes: []byte{0xc0}, BitLength: 3}, "\xa0", 3, false, false},
		{"two octets", BitString{Bytes: []byte{0xff, 0x80}, BitLength: 9}, "\xff\x80", 9, false, true},
		{"named trailing zeros", BitString{Bytes: []byte{0x40, 0x00}, BitLength: 16}, "\x40", 2, true, true},
		{"named default trailing zeros", BitString{Bytes: []byte{0x40}, BitLength: 2}, "\x40\x00", 12, true, true},
		{"named empty", BitString{}, "\x00", 3, true, true},
		{"named other bit", BitString{Bytes: []byte{0x60}, BitLength: 3}, "\x40", 2, true, false},
		{"unnamed trailing zeros", BitString{Bytes: []byte{0x40}, BitLength: 3}, "\x40", 2, false, false},
		{"short bytes", BitString{Bytes: []byte{0x40}, BitLength: 9}, "\x40\x00", 9, false, false},
		{"negative length", BitString{BitLength: -1}, "", 0, true, false},
		{"length beyond bytes", BitString{Bytes: []byte{0x40}, BitLength: math.MaxInt}, "\x40", 2, true, false},
		{"default beyond bytes", BitString{Bytes: []byte{0x40}, BitLength: 2}, "\x40", math.MaxInt, true, false},
	} {
		if got := test.value.EqualBits(test.bits, test.length, test.namedBits); got != test.want {
			t.Errorf("%s: EqualBits = %t, want %t", test.name, got, test.want)
		}
	}
}

// EqualBits never reads past its octets, a value equals itself, and with
// named bits appending zero bits keeps it equal.
