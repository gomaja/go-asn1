// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/tag/tag_test.go; SHA-256 02d506480a3e8e7ad1bccb90c50e2c78f9ff05f40201a4867c3154781b15742c.
package tag

import (
	"bytes"
	"testing"
)

func TestTagForms(t *testing.T) {
	// X.690 (02/2021) §8.1.2; Erratum 1 (09/2021), corrected Figure 4.
	for _, test := range []struct {
		tag  Tag
		wire []byte
		text string
	}{
		{Tag{ClassUniversal, TagSequence, true}, []byte{0x30}, "[UNIVERSAL 16 CONSTRUCTED]"},
		{Tag{ClassApplication, 31, false}, []byte{0x5f, 0x1f}, "[APPLICATION 31 PRIMITIVE]"},
		{Tag{ClassContextSpecific, 201, true}, []byte{0xbf, 0x81, 0x49}, "[CONTEXT 201 CONSTRUCTED]"},
		{Tag{ClassPrivate, 128, false}, []byte{0xdf, 0x81, 0}, "[PRIVATE 128 PRIMITIVE]"},
	} {
		if got := test.tag.Encode(); !bytes.Equal(got, test.wire) {
			t.Fatalf("%v: %x, want %x", test.tag, got, test.wire)
		}
		if got := test.tag.String(); got != test.text {
			t.Fatalf("%v: %q", test.tag, got)
		}
		if !test.tag.Equal(test.tag) || test.tag.Equal(Tag{test.tag.Class, test.tag.Number + 1, test.tag.Constructed}) {
			t.Fatal("tag identity differs")
		}
	}
	if got := Class(4).String(); got != "CLASS(4)" {
		t.Fatal(got)
	}
}
