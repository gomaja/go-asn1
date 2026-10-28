// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/unexpected_element_test.go; SHA-256 c1fdfd86fbf7988c7601a6d52045d7906f1b786148b944e7b845eb16ab598bde.
package ber

import (
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
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

func TestUnexpectedElementExcludesSchemaProfile(t *testing.T) {
	wire := []byte{0x4a, 0}
	opts := TrackTCAPForm(nil, "AbortReason", "source")
	if !errors.Is(ValidateBERElement(wire, opts...), ErrInvalidValue) {
		t.Fatal("profile control did not reject empty IMPLICIT INTEGER")
	}
	if err := unexpectedElementError(wire, opts); !errors.Is(err, ErrUnexpectedElement) {
		t.Fatal(err)
	}
}

// Generated EXTERNAL roots have a recursive structural preflight in every
// execution mode; no additional scan is added to these successful paths.
func TestGeneratedExternalUnexpectedElementValidation(t *testing.T) {
	for _, opts := range [][]DecodeOption{nil, {ForceGeneratedBERLightForTesting()}, {ForceGeneratedBERProofForTesting()}} {
		for name, wire := range universalRejectionElements(t) {
			t.Run(name, func(t *testing.T) {
				received, _, err := DecodeTag(wire)
				if err != nil {
					t.Fatal(err)
				}
				want := ValidateBERElement(wire)
				if received.Number != tag.TagExternal {
					_, _, _, got := DecodeGeneratedExternal(wire, opts, "")
					assertElementRejection(t, wire, got, want)
					wrapper, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 1, Constructed: true}, wire)
					if err != nil {
						t.Fatal(err)
					}
					_, _, _, got = DecodeGeneratedExternal(wrapper, opts, "EXPLICIT")
					assertElementRejection(t, wire, got, want)
				}
				if received.Number != tag.TagSequence {
					_, _, _, got := DecodeGeneratedExternalSequence(wire, opts)
					assertElementRejection(t, wire, got, want)
				}
			})
		}
	}
}
