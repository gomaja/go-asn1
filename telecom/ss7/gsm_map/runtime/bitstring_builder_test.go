// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/bitstring_builder_test.go; SHA-256 0206e02672945837ba69e409f1e04a0907d8373d1c9f4a591bcace7ce7253653.
package runtime

import (
	"bytes"
	"math"
	goruntime "runtime"
	"testing"
)

// These cases catch reversed bit numbering, implicit length changes, dropped
// boundary bits and treating repeated positions as a toggle.
func TestNewBitStringLogicalLengthAndPositions(t *testing.T) {
	cases := []struct {
		length int
		set    []int
		want   []byte
	}{
		{0, nil, nil}, {1, nil, []byte{0}}, {1, []int{0}, []byte{0x80}},
		{7, []int{0, 6}, []byte{0x82}}, {8, []int{0, 7}, []byte{0x81}},
		{9, []int{0, 7, 8, 8}, []byte{0x81, 0x80}},
		{16, []int{0, 15}, []byte{0x80, 1}}, {17, []int{16}, []byte{0, 0, 0x80}},
	}
	for _, tc := range cases {
		value, err := NewBitString(tc.length, tc.set...)
		if err != nil || value.BitLength != tc.length || !bytes.Equal(value.Bytes, tc.want) {
			t.Fatalf("length%d set%v: %+v %v", tc.length, tc.set, value, err)
		}
		for bit := 0; bit < tc.length; bit++ {
			want := false
			for _, selected := range tc.set {
				want = want || bit == selected
			}
			if value.Has(bit) != want {
				t.Fatalf("length%d bit%d", tc.length, bit)
			}
		}
	}
}

func TestNewBitStringRejectsInvalidBeforeAllocating(t *testing.T) {
	const maxBits = (16 << 20) * 8
	cases := []struct {
		length int
		set    []int
	}{
		{-1, nil}, {math.MaxInt, nil}, {maxBits + 1, nil},
		{0, []int{0}}, {1, []int{-1}}, {1, []int{1}}, {9, []int{math.MaxInt}},
	}
	for _, tc := range cases {
		value, err := NewBitString(tc.length, tc.set...)
		if err == nil || value.BitLength != 0 || len(value.Bytes) != 0 {
			t.Fatalf("invalid length%d set%v: %+v %v", tc.length, tc.set, value, err)
		}
	}
	var before, after goruntime.MemStats
	goruntime.ReadMemStats(&before)
	_, err := NewBitString(maxBits, -1)
	goruntime.ReadMemStats(&after)
	if err == nil || after.TotalAlloc-before.TotalAlloc > 1<<20 {
		t.Fatalf("invalid position allocated %d bytes: %v", after.TotalAlloc-before.TotalAlloc, err)
	}
	value, err := NewBitString(maxBits, maxBits-1)
	if err != nil || len(value.Bytes) != 16<<20 || value.BitLength != maxBits || value.Bytes[len(value.Bytes)-1] != 1 {
		t.Fatalf("allocation ceiling boundary: len%d bits%d %v", len(value.Bytes), value.BitLength, err)
	}
}

// Growing through dirty unused bits or stale slice capacity must expose only
// zero-filled new bits and the selected bit.
func TestBitStringSetGrowsAndNormalizes(t *testing.T) {
	backing := []byte{0xbf, 0xff, 0xff}
	value := BitString{Bytes: backing[:1], BitLength: 3}
	if err := value.Set(17); err != nil {
		t.Fatal(err)
	}
	if value.BitLength != 18 || !bytes.Equal(value.Bytes, []byte{0xa0, 0, 0x40}) {
		t.Fatalf("growth exposes stale bits: %+v", value)
	}
	if err := value.Set(17); err != nil || !bytes.Equal(value.Bytes, []byte{0xa0, 0, 0x40}) {
		t.Fatalf("repeated set toggled bit: %+v %v", value, err)
	}
	value = BitString{Bytes: []byte{0xbf}, BitLength: 3}
	if err := value.Set(5); err != nil || value.BitLength != 6 || !bytes.Equal(value.Bytes, []byte{0xa4}) {
		t.Fatalf("growth inside final octet: %+v %v", value, err)
	}
	value = BitString{Bytes: []byte{0x80, 0xff}, BitLength: 9}
	if err := value.Set(7); err != nil || value.BitLength != 9 || !bytes.Equal(value.Bytes, []byte{0x81, 0x80}) {
		t.Fatalf("in-range set: %+v %v", value, err)
	}
	var empty BitString
	if err := empty.Set(0); err != nil || empty.BitLength != 1 || !bytes.Equal(empty.Bytes, []byte{0x80}) {
		t.Fatalf("zero-value growth: %+v %v", empty, err)
	}
	const maxBits = (16 << 20) * 8
	edge := BitString{Bytes: make([]byte, 16<<20), BitLength: maxBits}
	if err := edge.Set(maxBits - 1); err != nil || edge.Bytes[len(edge.Bytes)-1] != 1 {
		t.Fatalf("last permitted bit: %v", err)
	}
}

func TestBitStringClearRetainsLengthAndNormalizes(t *testing.T) {
	value := BitString{Bytes: []byte{0xff, 0xff}, BitLength: 9}
	if err := value.Clear(0); err != nil || value.BitLength != 9 || !bytes.Equal(value.Bytes, []byte{0x7f, 0x80}) {
		t.Fatalf("clear first bit: %+v %v", value, err)
	}
	if err := value.Clear(8); err != nil || value.BitLength != 9 || !bytes.Equal(value.Bytes, []byte{0x7f, 0}) {
		t.Fatalf("clear last bit: %+v %v", value, err)
	}
	before := bytes.Clone(value.Bytes)
	if err := value.Clear(math.MaxInt); err != nil || value.BitLength != 9 || !bytes.Equal(value.Bytes, before) {
		t.Fatalf("beyond-length clear: %+v %v", value, err)
	}
	dirty := BitString{Bytes: []byte{0xbf}, BitLength: 3}
	if err := dirty.Clear(math.MaxInt); err != nil || dirty.BitLength != 3 || !bytes.Equal(dirty.Bytes, []byte{0xa0}) {
		t.Fatalf("logical no-op must normalize unused tail: %+v %v", dirty, err)
	}
	var empty BitString
	if err := empty.Clear(0); err != nil || empty.BitLength != 0 || len(empty.Bytes) != 0 {
		t.Fatalf("empty clear: %+v %v", empty, err)
	}
}

func TestBitStringInvalidMutationsAreAtomic(t *testing.T) {
	invalid := []BitString{
		{BitLength: -1}, {Bytes: []byte{0xaa}, BitLength: -1},
		{Bytes: nil, BitLength: 1}, {Bytes: []byte{0xaa}, BitLength: 9},
		{Bytes: []byte{0xaa}, BitLength: 0}, {Bytes: []byte{0xaa, 0xbb}, BitLength: 8},
		{Bytes: []byte{0xaa}, BitLength: math.MaxInt},
	}
	for _, initial := range invalid {
		for _, position := range []int{-1, 0, math.MaxInt} {
			for _, clear := range []bool{false, true} {
				value := BitString{Bytes: bytes.Clone(initial.Bytes), BitLength: initial.BitLength}
				before := bytes.Clone(value.Bytes)
				var err error
				if clear {
					err = value.Clear(position)
				} else {
					err = value.Set(position)
				}
				if err == nil || value.BitLength != initial.BitLength || !bytes.Equal(value.Bytes, before) {
					t.Fatalf("invalid mutation clear=%v position%d initial%+v became%+v: %v", clear, position, initial, value, err)
				}
			}
		}
	}
	for _, position := range []int{-1, (16 << 20) * 8, math.MaxInt} {
		value := BitString{Bytes: []byte{0xbf}, BitLength: 3}
		before := bytes.Clone(value.Bytes)
		if err := value.Set(position); err == nil || value.BitLength != 3 || !bytes.Equal(value.Bytes, before) {
			t.Fatalf("invalid set mutated value: %+v %v", value, err)
		}
	}
	value := BitString{Bytes: []byte{0xbf}, BitLength: 3}
	before := bytes.Clone(value.Bytes)
	if err := value.Clear(-1); err == nil || value.BitLength != 3 || !bytes.Equal(value.Bytes, before) {
		t.Fatalf("negative clear mutated value: %+v %v", value, err)
	}
	var absent *BitString
	if err := absent.Set(0); err == nil {
		t.Fatal("nil Set receiver")
	}
	if err := absent.Clear(0); err == nil {
		t.Fatal("nil Clear receiver")
	}
}
