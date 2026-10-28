// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/root_framing_test.go; SHA-256 ac3d5b68de78394ed449ac41e84408e46ffd38b2d9d65d411ac41baa263cacf5.
package ber

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §§8.1.2, 8.1.3, 8.1.5: a tag mismatch
// cannot establish a complete element until its framing is checked.
func TestWrongRootTagFraming(t *testing.T) {
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 1, Constructed: true}
	inner := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}
	for _, decoder := range []struct {
		name        string
		decode      func([]byte) error
		primitive   string
		constructed string
	}{
		{"octet string", func(b []byte) error { _, _, err := DecodeOctetString(b); return err }, "02", "30"},
		{"bit string", func(b []byte) error { _, _, _, err := DecodeBitString(b); return err }, "02", "30"},
		{"character string", func(b []byte) error { _, _, err := DecodeString(b, tag.TagUTF8String); return err }, "02", "30"},
		{"boolean", func(b []byte) error { _, _, _, err := DecodeBoolean(b); return err }, "02", "30"},
		{"integer", func(b []byte) error { _, _, err := DecodeInteger(b); return err }, "01", "30"},
		{"big integer", func(b []byte) error { _, _, err := DecodeBigInt(b); return err }, "01", "30"},
		{"unsigned integer", func(b []byte) error { _, _, err := DecodeUint64(b); return err }, "01", "30"},
		{"null", func(b []byte) error { _, err := DecodeNull(b); return err }, "02", "30"},
		{"object identifier", func(b []byte) error { _, _, err := DecodeObjectIdentifier(b); return err }, "02", "30"},
		{"relative identifier", func(b []byte) error { _, _, err := DecodeRelativeObjectIdentifier(b); return err }, "02", "30"},
		{"enumerated", func(b []byte) error { _, _, err := DecodeEnumerated(b); return err }, "02", "30"},
		{"real", func(b []byte) error { _, _, err := DecodeReal(b); return err }, "02", "30"},
		{"sequence", func(b []byte) error { _, _, err := DecodeSequenceContent(b); return err }, "02", "31"},
		{"external", func(b []byte) error { _, _, err := DecodeExternal(b); return err }, "02", "30"},
		{"implicit collection", func(b []byte) error { _, err := DecodeTaggedCollectionElement(b, outer, false, inner); return err }, "02", "30"},
		{"explicit collection", func(b []byte) error { _, err := DecodeTaggedCollectionElement(b, outer, true, inner); return err }, "02", "30"},
		{"dual tagged choice", func(b []byte) error { _, err := DecodeDualTaggedChoiceElement(b, outer, inner, true); return err }, "02", "30"},
	} {
		t.Run(decoder.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, wire string
				want       error
			}{
				{"missing length", decoder.primitive, ErrTruncated},
				{"missing value", decoder.primitive + "01", ErrTruncated},
				{"complete primitive", decoder.primitive + "0100", ErrUnexpectedElement},
				{"incomplete long length", decoder.primitive + "82ff", ErrTruncated},
				{"reserved length", decoder.primitive + "ff", ErrInvalidLength},
				{"primitive indefinite", decoder.primitive + "800000", ErrInvalidLength},
				{"missing EOC", decoder.constructed + "80", ErrTruncated},
				{"partial EOC", decoder.constructed + "8000", ErrTruncated},
				{"complete indefinite", decoder.constructed + "800000", ErrUnexpectedElement},
				{"nested missing EOC", decoder.constructed + "8030800000", ErrTruncated},
				{"nested complete indefinite", decoder.constructed + "80308000000000", ErrUnexpectedElement},
				{"invalid identifier", "1f8000", ErrInvalidTag},
				{"standalone EOC", "0000", ErrInvalidTag},
			} {
				t.Run(tc.name, func(t *testing.T) {
					wire, err := hex.DecodeString(tc.wire)
					if err != nil {
						t.Fatal(err)
					}
					got := decoder.decode(wire)
					for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit, ErrInvalidCodec, ErrInvalidBinding} {
						if errors.Is(got, sentinel) != (sentinel == tc.want) {
							t.Errorf("%s: error = %v, errors.Is(%v), want only %v", tc.wire, got, sentinel, tc.want)
						}
					}
				})
			}
		})
	}
}

// X.690 (02/2021) §§8.6.4, 8.7.3: an invalid child tag keeps
// precedence over the child's missing length inside a constructed string.
func TestWrongStringSegmentTagPrecedence(t *testing.T) {
	for _, tc := range []struct {
		wire   string
		decode func([]byte) error
	}{
		{"240102", func(b []byte) error { _, _, err := DecodeOctetString(b); return err }},
		{"230102", func(b []byte) error { _, _, _, err := DecodeBitString(b); return err }},
		{"2c0102", func(b []byte) error { _, _, err := DecodeString(b, tag.TagUTF8String); return err }},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		got := tc.decode(wire)
		if !errors.Is(got, ErrInvalidTag) || errors.Is(got, ErrTruncated) || errors.Is(got, ErrUnexpectedElement) {
			t.Errorf("%s: error = %v, want only invalid tag", tc.wire, got)
		}
	}
}
