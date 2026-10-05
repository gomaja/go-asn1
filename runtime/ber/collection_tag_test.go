package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestImplicitCollectionElementTracksNoncanonicalBERForm(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  []byte
		inner tag.Tag
	}{
		{"boolean true", []byte{0x85, 0x01, 0x01}, tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBoolean}},
		{"constructed bit string", []byte{0xa5, 0x08, 0x03, 0x02, 0x00, 0xaa, 0x03, 0x02, 0x04, 0xb0}, tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}},
		{"constructed IA5String", []byte{0xa5, 0x07, 0x04, 0x01, 'a', 0x04, 0x02, 'b', 'c'}, tag.Tag{Class: tag.ClassUniversal, Number: tag.TagIA5String}},
		{"decimal REAL", []byte{0x85, 0x02, 0x01, '1'}, tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}},
		{"constructed octet string", []byte{0xa5, 0x07, 0x04, 0x01, 0xaa, 0x04, 0x02, 0xbb, 0xcc}, tag.Tag{Class: tag.ClassUniversal, Number: tag.TagOctetString}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := TrackBERForm(nil)
			if err := ValidateBERElement(tc.wire, opts...); err != nil {
				t.Fatal(err)
			}
			if BERNeedsPreservation(opts) {
				t.Fatal("universal form was detected before retagging")
			}
			got, err := DecodeTaggedCollectionElement(tc.wire, tag.Tag{Class: tag.ClassContextSpecific, Number: 5}, false, tc.inner, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 || !bytes.Equal(got[1:], tc.wire[1:]) {
				t.Fatalf("retagged bytes = %x", got)
			}
			if !BERNeedsPreservation(opts) {
				t.Fatal("noncanonical implicit element was not preserved")
			}
		})
	}
}
