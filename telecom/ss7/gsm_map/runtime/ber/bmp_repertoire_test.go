// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/bmp_repertoire_test.go; SHA-256 1ca966ae24869b224c10e0e79732c87a3561a20b855b14b133869ca8b70a6289.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.680 (02/2021) §41.15 excludes the last two cells and surrogates.
func TestBMPStringRepertoireBoundary(t *testing.T) {
	for _, r := range []rune{0, 0xd7ff, 0xd800, 0xdfff, 0xe000, 0xfffd, 0xfffe, 0xffff} {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			valid := r < 0xd800 || r > 0xdfff && r <= 0xfffd
			contents := []byte{byte(r >> 8), byte(r)}
			primitive := append([]byte{30, 2}, contents...)
			constructed := []byte{62, 6, 4, 1, contents[0], 4, 1, contents[1]}
			indefinite := []byte{62, 128, 4, 1, contents[0], 4, 1, contents[1], 0, 0}
			check := func(name string, err error) {
				t.Helper()
				if valid && err != nil || !valid && !errors.Is(err, ErrInvalidValue) {
					t.Errorf("%s: %v; valid=%v", name, err, valid)
				}
			}
			for _, wire := range [][]byte{primitive, constructed, indefinite} {
				check("BER", ValidateBERElement(wire))
				var reports ViolationLog
				check("tolerant BER", ValidateBERElement(wire, WithTolerance(&reports)))
				_, _, err := DecodeString(wire, tag.TagBMPString)
				check("typed decode", err)
				_, _, err = DecodeString(wire, tag.TagBMPString, WithTolerance(&reports))
				check("tolerant typed decode", err)
			}
			check("DER", ValidateDEREncodedElement(primitive))
			_, err := DecodeStringValueTag(tag.TagBMPString, contents)
			check("contents decode", err)
			if r < 0xd800 || r > 0xdfff {
				encoded, err := EncodeStringTagChecked(tag.TagBMPString, string(r))
				check("typed encode", err)
				if valid && !bytes.Equal(encoded, primitive) {
					t.Fatal("changed BMPString encoding")
				}
			}
		})
	}
}

// §§41.6–41.7, 41.16 do not impose BMPString's 64K-2-cell restriction.
func TestOtherUnicodeStringsKeepScalarBoundary(t *testing.T) {
	for _, r := range []rune{0xfffd, 0xfffe, 0xffff, 0x10000, 0x10ffff} {
		for _, number := range []int{tag.TagUniversalString, tag.TagUTF8String} {
			wire, err := EncodeStringTagChecked(number, string(r))
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateBERElement(wire); err != nil {
				t.Fatal(err)
			}
			if err := ValidateDEREncodedElement(wire); err != nil {
				t.Fatal(err)
			}
			decoded, _, err := DecodeString(wire, number)
			if err != nil || decoded != string(r) {
				t.Fatalf("U+%04X tag %d: %q %v", r, number, decoded, err)
			}
		}
	}
}
