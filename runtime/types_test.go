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
func FuzzBitStringEqualBits(f *testing.F) {
	f.Add([]byte{0x40}, 2, []byte{0x40}, 3, true)
	f.Add([]byte{0xa0}, 3, []byte{0xa0}, 3, false)
	f.Add([]byte{}, 0, []byte{0x00}, 8, true)
	f.Fuzz(func(t *testing.T, left []byte, leftLength int, right []byte, rightLength int, namedBits bool) {
		value := BitString{Bytes: left, BitLength: leftLength}
		equal := value.EqualBits(string(right), rightLength, namedBits)
		if leftLength < 0 || leftLength > 8*len(left) {
			if equal {
				t.Fatalf("%x/%d does not hold its bits but equals %x/%d", left, leftLength, right, rightLength)
			}
			return
		}
		if !value.EqualBits(string(left), leftLength, namedBits) {
			t.Fatalf("%x/%d differs from itself", left, leftLength)
		}
		if namedBits {
			// The bits after BitLength are unused; clear them before extending.
			extended := append(append([]byte(nil), left[:(leftLength+7)/8]...), 0)
			if leftLength%8 != 0 {
				extended[leftLength/8] &= byte(0xff) << uint(8-leftLength%8)
			}
			if !value.EqualBits(string(extended), leftLength+8, true) {
				t.Fatalf("%x/%d differs from itself with eight more zero bits", left, leftLength)
			}
		}
		if rightLength >= 0 && rightLength <= 8*len(right) && equal != (BitString{Bytes: right, BitLength: rightLength}).EqualBits(string(left), leftLength, namedBits) {
			t.Fatalf("EqualBits is not symmetric for %x/%d and %x/%d", left, leftLength, right, rightLength)
		}
	})
}
