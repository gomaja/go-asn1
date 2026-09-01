package ber

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestFixedWidthStringTagsUseX690CodeUnits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tagNum int
		value  string
		wire   string
	}{
		{name: "BMP ASCII", tagNum: tag.TagBMPString, value: "hello", wire: "1e0a00680065006c006c006f"},
		{name: "BMP non-ASCII", tagNum: tag.TagBMPString, value: "\u20ac", wire: "1e0220ac"},
		{name: "Universal ASCII", tagNum: tag.TagUniversalString, value: "A", wire: "1c0400000041"},
		{name: "Universal supplementary", tagNum: tag.TagUniversalString, value: "\U0001f600", wire: "1c040001f600"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			want, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := EncodeStringTagChecked(test.tagNum, test.value)
			if err != nil {
				t.Fatalf("EncodeStringTagChecked() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("EncodeStringTagChecked() = %x, want %x", got, want)
			}
			if legacy := EncodeStringTag(test.tagNum, test.value); !bytes.Equal(legacy, want) {
				t.Fatalf("EncodeStringTag() = %x, want %x", legacy, want)
			}
			decoded, consumed, err := DecodeString(got, test.tagNum)
			if err != nil {
				t.Fatalf("DecodeString() error = %v", err)
			}
			if decoded != test.value || consumed != len(got) {
				t.Fatalf("DecodeString() = %q, %d, want %q, %d", decoded, consumed, test.value, len(got))
			}
		})
	}
}

func TestFixedWidthStringTagsRejectUnrepresentableValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tagNum int
		value  string
	}{
		{name: "BMP supplementary", tagNum: tag.TagBMPString, value: "\U0001f600"},
		{name: "BMP invalid UTF-8", tagNum: tag.TagBMPString, value: string([]byte{0xff})},
		{name: "Universal invalid UTF-8", tagNum: tag.TagUniversalString, value: string([]byte{0xff})},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if encoded, err := EncodeStringTagChecked(test.tagNum, test.value); err == nil || encoded != nil {
				t.Fatalf("EncodeStringTagChecked() = %x, %v, want nil error result", encoded, err)
			}
		})
	}
}

func TestFixedWidthStringTagsRejectMalformedWireValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tagNum int
		wire   string
	}{
		{name: "BMP odd width", tagNum: tag.TagBMPString, wire: "1e0100"},
		{name: "BMP surrogate", tagNum: tag.TagBMPString, wire: "1e02d800"},
		{name: "Universal wrong width", tagNum: tag.TagUniversalString, wire: "1c03000000"},
		{name: "Universal surrogate", tagNum: tag.TagUniversalString, wire: "1c040000d800"},
		{name: "Universal out of range", tagNum: tag.TagUniversalString, wire: "1c0400110000"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := DecodeString(wire, test.tagNum); err == nil {
				t.Fatal("DecodeString() accepted malformed fixed-width string")
			}
		})
	}
}

func FuzzDecodeFixedWidthString(f *testing.F) {
	for _, seed := range []struct {
		tagNum int
		value  []byte
	}{
		{tagNum: tag.TagBMPString, value: []byte{0x00, 0x41}},
		{tagNum: tag.TagBMPString, value: []byte{0xd8, 0x00}},
		{tagNum: tag.TagUniversalString, value: []byte{0x00, 0x01, 0xf6, 0x00}},
		{tagNum: tag.TagUniversalString, value: []byte{0x00, 0x11, 0x00, 0x00}},
	} {
		f.Add(seed.tagNum, seed.value)
	}
	f.Fuzz(func(t *testing.T, tagNum int, value []byte) {
		if tagNum != tag.TagBMPString && tagNum != tag.TagUniversalString {
			t.Skip()
		}
		decoded, err := DecodeStringValueTag(tagNum, value)
		if err != nil {
			return
		}
		encoded, err := encodeStringValueTag(tagNum, decoded)
		if err != nil {
			t.Fatalf("decoded value cannot be re-encoded: %v", err)
		}
		if !bytes.Equal(encoded, value) {
			t.Fatalf("round trip = %x, want %x", encoded, value)
		}
	})
}

func TestStringTagErrorsNameTheEncoding(t *testing.T) {
	t.Parallel()

	_, err := EncodeStringTagChecked(tag.TagBMPString, "\U0001f600")
	if err == nil || !strings.Contains(err.Error(), "BMPString") {
		t.Fatalf("EncodeStringTagChecked() error = %v, want BMPString context", err)
	}
}
