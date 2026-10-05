package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func TestNormalizeNamedBitStringSize(t *testing.T) {
	for _, tc := range []struct {
		name       string
		input      runtime.BitString
		sets       []NamedBitSizeSet
		wantLength int
		wantBytes  []byte
		preserve   bool
	}{
		{"minimum", runtime.BitString{Bytes: []byte{0x40}, BitLength: 2}, []NamedBitSizeSet{{{Min: 8, Max: 16}}}, 8, []byte{0x40}, true},
		{"BER unused bits are not value bits", runtime.BitString{Bytes: []byte{0x41}, BitLength: 2}, []NamedBitSizeSet{{{Min: 8, Max: 16}}}, 8, []byte{0x40}, true},
		{"BER unused bits before another octet", runtime.BitString{Bytes: []byte{0x41}, BitLength: 2}, []NamedBitSizeSet{{{Min: 16, Max: 16}}}, 16, []byte{0x40, 0x00}, true},
		{"intersecting disjoint sets", runtime.BitString{Bytes: []byte{0x40}, BitLength: 2}, []NamedBitSizeSet{{{Min: 1, Max: 1}, {Min: 4, Max: 4}}, {{Min: 3, Max: 4}}}, 4, []byte{0x40}, true},
		{"empty named bits", runtime.BitString{}, []NamedBitSizeSet{{{Min: 3, Max: 8}}}, 3, []byte{0x00}, true},
		{"already permitted", runtime.BitString{Bytes: []byte{0x40}, BitLength: 2}, []NamedBitSizeSet{{{Min: 1, Max: 4}}}, 2, []byte{0x40}, false},
		{"too long", runtime.BitString{Bytes: []byte{0x40}, BitLength: 2}, []NamedBitSizeSet{{{Min: 0, Max: 1}}}, 2, []byte{0x40}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := TrackBERForm(nil)
			got := NormalizeNamedBitStringSize(tc.input, tc.sets, opts...)
			if got.BitLength != tc.wantLength || !bytes.Equal(got.Bytes, tc.wantBytes) || BERNeedsPreservation(opts) != tc.preserve {
				t.Fatalf("normalized = (%x, %d), preserve=%t", got.Bytes, got.BitLength, BERNeedsPreservation(opts))
			}
		})
	}
}
