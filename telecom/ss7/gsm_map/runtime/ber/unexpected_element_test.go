// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/unexpected_element_test.go; SHA-256 7f5351f2448bbe2ea41cfb4cfc96dc9ef5f87e3c64345b230d30d5800d6a53fd.
package ber

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §§8.1–8.26: abstract-syntax rejection follows the
// same recursive BER checks used by the public element validator.
func universalRejectionElements(t *testing.T) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for number := 1; number <= 36; number++ {
		if number == 15 {
			continue
		}
		constructed := number == tag.TagSequence || number == tag.TagSet || number == tag.TagExternal || number == tag.TagEmbeddedPDV || number == tag.TagCharacterString
		var contents []byte
		switch number {
		case tag.TagBoolean, tag.TagInteger, tag.TagEnumerated, tag.TagBitString:
			contents = []byte{0}
		case tag.TagObjectID, tag.TagRelativeOID:
			contents = []byte{42}
		case tag.TagUTF8String:
			contents = []byte{'a'}
		}
		for _, variant := range []struct {
			name     string
			form     bool
			contents []byte
		}{
			{"valid", constructed, contents}, {"opposite-form", !constructed, nil},
		} {
			wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: variant.form}, variant.contents)
			if err != nil {
				t.Fatal(err)
			}
			result[fmt.Sprintf("tag-%d/%s", number, variant.name)] = wire
		}
		invalid := [][]byte(nil)
		switch number {
		case tag.TagBoolean:
			invalid = [][]byte{{}, {0, 0}}
		case tag.TagNull:
			invalid = [][]byte{{0}}
		case tag.TagInteger, tag.TagEnumerated:
			invalid = [][]byte{{}, {0, 1}, {255, 255}}
		case tag.TagBitString:
			invalid = [][]byte{{}, {8}, {1}}
		case tag.TagObjectID, tag.TagRelativeOID:
			invalid = [][]byte{{}, {128}, {128, 42}}
		case tag.TagUTF8String:
			invalid = [][]byte{{255}}
		}
		if constructed {
			invalid = [][]byte{{2, 0}, {0x22, 0}, {5}, {0x30, 2, 2, 0}}
		}
		for i, contents := range invalid {
			wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: constructed}, contents)
			if err != nil {
				t.Fatal(err)
			}
			result[fmt.Sprintf("tag-%d/invalid-contents-%d", number, i)] = wire
		}
	}
	return result
}

func assertElementRejection(t *testing.T, wire []byte, got, want error) {
	t.Helper()
	if want == nil {
		want = ErrUnexpectedElement
	}
	for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit} {
		if errors.Is(got, sentinel) != errors.Is(want, sentinel) {
			t.Errorf("%x: got %v, validator %v, errors.Is(%v) differs", wire, got, want, sentinel)
		}
	}
}

func TestUnexpectedElementUniversalValidation(t *testing.T) {
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 1, Constructed: true}
	inner := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}
	for _, decoder := range []struct {
		name   string
		number int
		decode func([]byte) error
	}{
		{"boolean", tag.TagBoolean, func(b []byte) error { _, _, _, e := DecodeBoolean(b); return e }},
		{"integer", tag.TagInteger, func(b []byte) error { _, _, e := DecodeInteger(b); return e }},
		{"big integer", tag.TagInteger, func(b []byte) error { _, _, e := DecodeBigInt(b); return e }},
		{"unsigned integer", tag.TagInteger, func(b []byte) error { _, _, e := DecodeUint64(b); return e }},
		{"null", tag.TagNull, func(b []byte) error { _, e := DecodeNull(b); return e }},
		{"object identifier", tag.TagObjectID, func(b []byte) error { _, _, e := DecodeObjectIdentifier(b); return e }},
		{"relative identifier", tag.TagRelativeOID, func(b []byte) error { _, _, e := DecodeRelativeObjectIdentifier(b); return e }},
		{"enumerated", tag.TagEnumerated, func(b []byte) error { _, _, e := DecodeEnumerated(b); return e }},
		{"real", tag.TagReal, func(b []byte) error { _, _, e := DecodeReal(b); return e }},
		{"octet string", tag.TagOctetString, func(b []byte) error { _, _, e := DecodeOctetString(b); return e }},
		{"bit string", tag.TagBitString, func(b []byte) error { _, _, _, e := DecodeBitString(b); return e }},
		{"character string", tag.TagUTF8String, func(b []byte) error { _, _, e := DecodeString(b, tag.TagUTF8String); return e }},
		{"sequence", tag.TagSequence, func(b []byte) error { _, _, e := DecodeSequenceContent(b); return e }},
		{"external", tag.TagExternal, func(b []byte) error { _, _, e := DecodeExternal(b); return e }},
		{"implicit collection", -1, func(b []byte) error { _, e := DecodeTaggedCollectionElement(b, outer, false, inner); return e }},
		{"explicit collection", -1, func(b []byte) error { _, e := DecodeTaggedCollectionElement(b, outer, true, inner); return e }},
		{"dual tagged choice", -1, func(b []byte) error { _, e := DecodeDualTaggedChoiceElement(b, outer, inner, true); return e }},
	} {
		t.Run(decoder.name, func(t *testing.T) {
			for name, wire := range universalRejectionElements(t) {
				received, _, err := DecodeTag(wire)
				if err != nil {
					t.Fatal(err)
				}
				// Matching identifiers exercise the selected type, not this rejection path.
				if received.Number == decoder.number {
					continue
				}
				t.Run(name, func(t *testing.T) { assertElementRejection(t, wire, decoder.decode(wire), ValidateBERElement(wire)) })
			}
		})
	}
}

func TestUnexpectedElementLiteralClassification(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want error
	}{
		{"2200", ErrInvalidTag}, {"2500", ErrInvalidTag}, {"1000", ErrInvalidTag},
		{"050100", ErrInvalidValue}, {"0200", ErrInvalidValue}, {"02020001", ErrInvalidValue},
		{"020100", ErrUnexpectedElement}, {"0500", ErrUnexpectedElement},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, got := DecodeBoolean(wire)
		assertElementRejection(t, wire, got, tc.want)
	}
}

// A rejection-only recursive scan must not move onto a successful prefix
// decoder's path. Constructed UTF8String validation requires scratch storage.
func TestUnexpectedElementSuccessAllocations(t *testing.T) {
	wire := []byte{0x30, 5, 0x2c, 3, 4, 1, 'a'}
	var failure error
	allocations := testing.AllocsPerRun(100, func() { _, _, failure = DecodeSequenceContent(wire) })
	if failure != nil {
		t.Fatal(failure)
	}
	if allocations != 0 {
		t.Fatalf("successful sequence allocations = %g, want 0", allocations)
	}
}

// X.690 (02/2021) §§8.14.3, 8.18.1: when one value is required,
// validate the rejected contents as a whole, not only its extra tail.
func TestUnexpectedElementNestedUniversalValidation(t *testing.T) {
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 1, Constructed: true}
	inner := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}
	for name, wire := range universalRejectionElements(t) {
		t.Run(name, func(t *testing.T) {
			want := ValidateBERElement(wire)
			wrapped, err := EncodeTLV(outer, append(append([]byte(nil), wire...), 5, 0))
			if err != nil {
				t.Fatal(err)
			}
			unknown, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 3, Constructed: true}, wire)
			if err != nil {
				t.Fatal(err)
			}
			single, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 0, Constructed: true}, wire)
			if err != nil {
				t.Fatal(err)
			}
			externalChoice := append([]byte{6, 1, 42}, unknown...)
			externalExtra := append(append([]byte{6, 1, 42}, single...), 5, 0)
			_, explicitErr := DecodeTaggedCollectionElement(wrapped, outer, true, inner)
			_, dualErr := DecodeDualTaggedChoiceElement(wrapped, outer, inner, true)
			_, externalErr := DecodeExternalValue(externalChoice)
			_, externalExtraErr := DecodeExternalValue(externalExtra)
			for _, got := range []error{explicitErr, dualErr, externalErr, externalExtraErr} {
				assertElementRejection(t, wire, got, want)
			}
		})
	}
}

func TestUnexpectedElementValidationLimits(t *testing.T) {
	// All three limits still apply to recursively rejected elements.
	wire := []byte{0x30, 5, 0x30, 3, 2, 1, 0}
	for _, limits := range []DecodeLimits{{MaxDepth: 1}, {MaxElements: 2}, {MaxWork: 6}} {
		for _, decode := range []func([]byte, ...DecodeOption) error{
			func(b []byte, opts ...DecodeOption) error { _, _, _, err := DecodeBoolean(b, opts...); return err },
			func(b []byte, opts ...DecodeOption) error { _, _, err := DecodeOctetString(b, opts...); return err },
			func(b []byte, opts ...DecodeOption) error { _, _, _, err := DecodeBitString(b, opts...); return err },
			func(b []byte, opts ...DecodeOption) error {
				_, _, err := DecodeString(b, tag.TagUTF8String, opts...)
				return err
			},
		} {
			err := decode(wire, WithDecodeLimits(limits))
			if !errors.Is(err, ErrResourceLimit) || errors.Is(err, ErrUnexpectedElement) {
				t.Fatalf("limits %+v: %v", limits, err)
			}
		}
	}
	// Sibling scans share one element/work allowance rather than resetting it
	// for each value. No synthetic enclosing element consumes the depth limit.
	siblings := []byte{5, 0, 5, 0, 5, 0}
	for _, limits := range []DecodeLimits{{MaxElements: 2}, {MaxWork: 5}} {
		err := validateExtraElements(siblings, []DecodeOption{WithDecodeLimits(limits)})
		if !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("sibling limits %+v: %v", limits, err)
		}
	}
	if err := validateExtraElements(siblings, []DecodeOption{WithDecodeLimits(DecodeLimits{MaxElements: 3, MaxWork: 6, MaxDepth: 1})}); err != nil {
		t.Fatal(err)
	}
	// The prefix decoder validates only the selected complete element. Bytes
	// after it remain the top-level caller's responsibility.
	_, _, _, err := DecodeBoolean([]byte{5, 0, 2})
	if !errors.Is(err, ErrUnexpectedElement) {
		t.Fatal(err)
	}
}

func TestUnexpectedElementSiblingBudgetGrowth(t *testing.T) {
	for _, count := range []int{32, 128, 512} {
		wire := make([]byte, 2*count)
		for i := 0; i < len(wire); i += 2 {
			wire[i] = 5
		}
		limits := DecodeLimits{MaxWork: len(wire), MaxElements: count, MaxDepth: 1}
		if err := validateExtraElements(wire, []DecodeOption{WithDecodeLimits(limits)}); err != nil {
			t.Fatal(err)
		}
		limits.MaxWork--
		if err := validateExtraElements(wire, []DecodeOption{WithDecodeLimits(limits)}); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("%d siblings: %v", count, err)
		}
		limits.MaxWork++
		limits.MaxElements--
		if err := validateExtraElements(wire, []DecodeOption{WithDecodeLimits(limits)}); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("%d siblings: %v", count, err)
		}
	}
}

// Even an unusual caller-selected universal outer tag must not let a
// malformed wrapper become a missing/extra-value mismatch (X.690 §8.3.1).
func TestUnexpectedElementValidatesReceivedWrapper(t *testing.T) {
	inner := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}
	for _, text := range []string{"2200", "2500", "220405000500", "250405000500"} {
		wire, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		outer, _, err := DecodeTag(wire)
		if err != nil {
			t.Fatal(err)
		}
		_, explicitErr := DecodeTaggedCollectionElement(wire, outer, true, inner)
		_, dualErr := DecodeDualTaggedChoiceElement(wire, outer, inner, true)
		for _, got := range []error{explicitErr, dualErr} {
			assertElementRejection(t, wire, got, ErrInvalidTag)
		}
	}
}

func TestUnexpectedElementExcludesSchemaProfile(t *testing.T) {
	wire := []byte{5, 0}
	opts := TrackMAPForm(nil)
	if !errors.Is(ValidateBERElement(wire, opts...), ErrInvalidValue) {
		t.Fatal("MAP profile control did not require a generated root")
	}
	if err := unexpectedElementError(wire, opts); !errors.Is(err, ErrUnexpectedElement) {
		t.Fatal(err)
	}
}
