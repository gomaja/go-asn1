// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/named_bit_input_padding_test.go; SHA-256 983b2962020b4fdb63604adb057c390f6704b78a5a88aba6db1b293ed473d1e7.
package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestNamedBitInputPaddingBeforeExtension(t *testing.T) {
	value := runtime.BitString{Bytes: []byte{0xff}, BitLength: 1}
	got, err := NormalizeNamedBitStringForEncoding(value, []NamedBitSizeSet{{{Min: 3, Max: 8}}})
	if err != nil || got.BitLength != 3 || !bytes.Equal(got.Bytes, []byte{0x80}) {
		t.Fatalf("input padding became logical bits: got %#v, %v", got, err)
	}
	if value.Bytes[0] != 0xff || value.BitLength != 1 {
		t.Fatalf("changed caller: %#v", value)
	}
}

func TestUnconstrainedNamedBitDecodeTracksTrailingZeros(t *testing.T) {
	for _, test := range []struct {
		length   int
		bytes    []byte
		want     int
		preserve bool
	}{
		{8, []byte{0x80}, 1, true},
		{1, []byte{0x80}, 1, false},
		{8, []byte{0}, 0, true},
	} {
		options := TrackBERForm(nil)
		before := append([]byte(nil), test.bytes...)
		got := NormalizeNamedBitStringSize(runtime.BitString{Bytes: test.bytes, BitLength: test.length}, nil, options...)
		if got.BitLength != test.want || BERNeedsPreservation(options) != test.preserve {
			t.Fatalf("%d: got %+v preserve=%v", test.length, got, BERNeedsPreservation(options))
		}
		if !bytes.Equal(test.bytes, before) {
			t.Fatal("changed received value bytes")
		}
	}
}
