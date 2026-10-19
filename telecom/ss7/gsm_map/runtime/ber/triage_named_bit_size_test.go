// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/triage_named_bit_size_test.go; SHA-256 ee34dfa843a4b5ee4f85c8ffa76b37fafc6e6b467f6b49a3784c132000b76653.
package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// X.680 (02/2021) §22.7 and X.690 (02/2021) §§8.6.2.4, 11.2.2 NOTE 1.
func TestBERNamedBitZeroTrimming(t *testing.T) {
	for _, tc := range []struct {
		name   string
		value  runtime.BitString
		sets   []NamedBitSizeSet
		length int
		want   []byte
	}{
		{"phase1", runtime.BitString{Bytes: []byte{0x80, 0, 0}, BitLength: 17}, []NamedBitSizeSet{{{1, 16}}}, 1, []byte{0x80}},
		{"fixed", runtime.BitString{Bytes: []byte{0x80, 0, 0}, BitLength: 17}, []NamedBitSizeSet{{{7, 7}}}, 7, []byte{0x80}},
		{"bit8", runtime.BitString{Bytes: []byte{0, 0x80, 0, 0, 0, 0}, BitLength: 48}, []NamedBitSizeSet{{{26, 40}}}, 26, []byte{0, 0x80, 0, 0}},
		{"zero", runtime.BitString{Bytes: make([]byte, 6), BitLength: 48}, []NamedBitSizeSet{{{26, 40}}}, 26, make([]byte, 4)},
		{"zero to empty", runtime.BitString{Bytes: []byte{0}, BitLength: 8}, []NamedBitSizeSet{{{0, 0}}}, 0, []byte{}},
		{"dirty padding", runtime.BitString{Bytes: []byte{0x81}, BitLength: 1}, []NamedBitSizeSet{{{7, 7}}}, 7, []byte{0x80}},
		{"disjoint intersection", runtime.BitString{Bytes: []byte{0x80, 0}, BitLength: 16}, []NamedBitSizeSet{{{2, 4}, {7, 9}}, {{5, 8}}}, 7, []byte{0x80}},
		{"unbounded", runtime.BitString{Bytes: []byte{0x80, 0}, BitLength: 16}, []NamedBitSizeSet{{{3, -1}}}, 3, []byte{0x80}},
		{"set bit cannot trim", runtime.BitString{Bytes: []byte{0, 0, 0, 0, 0, 1}, BitLength: 48}, []NamedBitSizeSet{{{26, 40}}}, 48, []byte{0, 0, 0, 0, 0, 1}},
		{"empty intersection", runtime.BitString{Bytes: []byte{0x80}, BitLength: 8}, []NamedBitSizeSet{{{1, 2}}, {{3, 4}}}, 8, []byte{0x80}},
		{"empty set", runtime.BitString{Bytes: []byte{0x80}, BitLength: 8}, []NamedBitSizeSet{{}}, 8, []byte{0x80}},
		{"malformed short", runtime.BitString{Bytes: []byte{}, BitLength: 8}, []NamedBitSizeSet{{{1, 1}}}, 8, []byte{}},
		{"max set bit", runtime.BitString{Bytes: []byte{0x80, 1}, BitLength: 16}, []NamedBitSizeSet{{{1, 16}}}, 16, []byte{0x80, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.value.Bytes)
			opts := TrackBERForm(nil)
			got := NormalizeNamedBitStringSize(tc.value, tc.sets, opts...)
			if got.BitLength != tc.length || !bytes.Equal(got.Bytes, tc.want) {
				t.Fatalf("got %x/%d want %x/%d", got.Bytes, got.BitLength, tc.want, tc.length)
			}
			if !bytes.Equal(tc.value.Bytes, original) {
				t.Fatal("normalizer changed input")
			}
			if (tc.length != tc.value.BitLength) != BERNeedsPreservation(opts) {
				t.Fatal("normalization form not tracked")
			}
		})
	}
	// Unnamed BIT STRING decoding keeps every transmitted value bit.
	got, u, n, err := DecodeBitString([]byte{3, 4, 7, 0x80, 0, 0})
	if err != nil || n != 6 || u != 7 || len(got) != 3 {
		t.Fatalf("unnamed got %x/%d %v", got, u, err)
	}
}
