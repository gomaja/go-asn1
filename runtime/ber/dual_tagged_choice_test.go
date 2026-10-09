package ber

import (
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func FuzzDecodeDualTaggedChoiceElement(f *testing.F) {
	for _, seed := range [][]byte{
		{0xa1, 0x06, 0xbf, 0x41, 0x03, 0x81, 0x01, 0x05},
		{0xa1, 0x03, 0x81, 0x01, 0x05},
		{0xa1, 0x80, 0x81, 0x01, 0x05, 0x00, 0x00},
		{0xa1, 0x06, 0x81, 0x01, 0x05, 0x82, 0x01, 0x06},
		{0xa1, 0x09, 0xbf, 0x41, 0x03, 0x81, 0x01, 0x05, 0x81, 0x01, 0x05},
		{0xa1, 0x06, 0x9f, 0x41, 0x03, 0x81, 0x01, 0x05},
		{0x81, 0x03, 0x81, 0x01, 0x05},
	} {
		f.Add(seed)
	}
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 1}
	inner := tag.Tag{Class: tag.ClassContextSpecific, Number: 65}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, explicit := range []bool{false, true} {
			normalized, err := DecodeDualTaggedChoiceElement(data, outer, inner, explicit)
			if err != nil {
				continue
			}
			actual, used, _, err := DecodeTLV(normalized)
			if err != nil || used != len(normalized) || actual.Class != inner.Class || actual.Number != inner.Number || !actual.Constructed {
				t.Fatalf("normalized tag=%v used=%d length=%d error=%v", actual, used, len(normalized), err)
			}
		}
	})
}

func TestDualTaggedChoiceRejectsInvalidInnerEncoding(t *testing.T) {
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 1}
	inner := tag.Tag{Class: tag.ClassContextSpecific, Number: 65}
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"trailing value", []byte{0xa1, 0x09, 0xbf, 0x41, 0x03, 0x81, 0x01, 0x05, 0x81, 0x01, 0x05}},
		{"primitive choice tag", []byte{0xa1, 0x06, 0x9f, 0x41, 0x03, 0x81, 0x01, 0x05}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, canonicalExplicit := range []bool{false, true} {
				if _, err := DecodeDualTaggedChoiceElement(tc.wire, outer, inner, canonicalExplicit); err == nil {
					t.Fatalf("accepted %x with canonicalExplicit=%t", tc.wire, canonicalExplicit)
				}
			}
		})
	}
}
