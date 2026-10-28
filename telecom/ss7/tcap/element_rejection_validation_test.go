package tcap

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
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
			wire, err := ber.EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: variant.form}, variant.contents)
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
			wire, err := ber.EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: constructed}, contents)
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
		want = ber.ErrUnexpectedElement
	}
	for _, sentinel := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
		if errors.Is(got, sentinel) != errors.Is(want, sentinel) {
			t.Errorf("%x: got %v, validator %v, errors.Is(%v) differs", wire, got, want, sentinel)
		}
	}
}

func TestTypedUnexpectedElementUniversalValidation(t *testing.T) {
	for _, opts := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
		for name, wire := range universalRejectionElements(t) {
			t.Run(name, func(t *testing.T) {
				want := ber.ValidateBERElement(wire)
				var root TCMessage
				var component Begin
				envelope, err := ber.EncodeTLV(tag.Tag{Class: tag.ClassApplication, Number: 2, Constructed: true}, wire)
				if err != nil {
					t.Fatal(err)
				}
				for _, got := range []error{root.UnmarshalBER(wire, opts...), component.UnmarshalBER(envelope, opts...)} {
					// The public TCAP roots retain their existing primitive
					// string encoding profile. The generic emitter matrix
					// separately tests these two well-formed BER encodings.
					if wire[0] == 0x23 || wire[0] == 0x24 {
						var profile *ber.ValidationError
						if !errors.As(got, &profile) {
							t.Fatalf("%x: expected existing profile refusal, got %v", wire, got)
						}
						assertElementRejection(t, wire, got, ber.ErrInvalidValue)
						continue
					}
					assertElementRejection(t, wire, got, want)
				}
			})
		}
	}
}
