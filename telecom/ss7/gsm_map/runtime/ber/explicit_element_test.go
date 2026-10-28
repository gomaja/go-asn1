// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/explicit_element_test.go; SHA-256 b293248cc4de9b7f61bdf2bfad96d0a7fc7c46af9868ec9aed2ff1d01db14dcf.
package ber

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func assertElementSentinels(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("error=%v, want %v", got, want)
	}
	for _, sentinel := range []error{ErrUnexpectedElement, ErrTruncated, ErrInvalidTag, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit} {
		if errors.Is(got, sentinel) != (want == sentinel) {
			t.Errorf("%v: errors.Is(%v)=%t, want %t", got, sentinel, errors.Is(got, sentinel), want == sentinel)
		}
	}
}

// X.690 (02/2021) §§8.1.2–8.1.3, 8.14.3, 8.18.1: complete
// wrappers missing a value differ from tails missing encoding octets.
func TestExplicitElementClassification(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want error
	}{
		{"280906022a03a003050005", ErrTruncated},
		{"280b06022a03a00505001f8000", ErrInvalidTag},
		{"280a06022a03a00405000500", ErrUnexpectedElement},
		{"280606022a03a000", ErrUnexpectedElement},
		{"280706022a03a00105", ErrTruncated},
		{"2800", ErrInvalidValue},
		{"280b06022a03a0050500300105", ErrTruncated},
		{"280a06022a03a00405002200", ErrInvalidTag},
	} {
		t.Run("EXTERNAL/"+tc.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = DecodeExternal(wire)
			assertElementSentinels(t, err, tc.want)
			_, err = DecodeExternalValue(wire[2:])
			assertElementSentinels(t, err, tc.want)
		})
	}
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 1, Constructed: true}
	inner := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}
	for _, tc := range []struct {
		wire string
		want error
	}{
		{"a103050005", ErrTruncated},
		{"a1060500051f8000", ErrTruncated},
		{"a10505001f8000", ErrInvalidTag},
		{"a10405000500", ErrUnexpectedElement},
		{"a100", ErrUnexpectedElement},
		{"a10105", ErrTruncated},
		{"a1020501", ErrTruncated},
		{"a1050500300105", ErrTruncated},
		{"a10405002200", ErrInvalidTag},
	} {
		t.Run("tagged/"+tc.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeTaggedCollectionElement(wire, outer, true, inner)
			assertElementSentinels(t, err, tc.want)
			_, err = DecodeDualTaggedChoiceElement(wire, outer, inner, true)
			assertElementSentinels(t, err, tc.want)
		})
	}
}
