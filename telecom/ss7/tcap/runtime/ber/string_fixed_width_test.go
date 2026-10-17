// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_fixed_width_test.go; SHA-256 c6c0e6e64760fa94f5269d137b95292acc219eb2332596e28572ec404df020f2.
package ber

import (
	"bytes"
	"encoding/hex"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"strings"
	"testing"
)

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

func TestFixedWidthStringTagsDecodeConstructedForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tagNum int
		wire   string
		want   string
	}{
		{name: "nested BMPString", tagNum: tag.TagBMPString, wire: "3e0a040200412404040203a9", want: "A\u03a9"},
		{name: "split BMPString code unit", tagNum: tag.TagBMPString, wire: "3e06040100040141", want: "A"},
		{name: "UniversalString", tagNum: tag.TagUniversalString, wire: "3c0c04040000004104040001f600", want: "A\U0001f600"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			got, consumed, err := DecodeString(wire, test.tagNum)
			if err != nil {
				t.Fatalf("DecodeString() error = %v", err)
			}
			if got != test.want || consumed != len(wire) {
				t.Fatalf("DecodeString() = %q, %d, want %q, %d", got, consumed, test.want, len(wire))
			}
		})
	}
}

func TestConstructedStringRejectsDifferentChildTag(t *testing.T) {
	t.Parallel()

	wire, err := hex.DecodeString("3e03120141")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeString(wire, tag.TagBMPString); err == nil {
		t.Fatal("DecodeString() accepted a constructed BMPString with a NumericString child")
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
