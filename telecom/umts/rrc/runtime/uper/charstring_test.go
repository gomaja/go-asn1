// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/charstring_test.go; SHA-256 6920ea09bdc7570d8b87054470ddbb35fc31e7b3545025f4255d4753bd11aa8b.
package uper

import (
	"bytes"
	"encoding/hex"
	"testing"
) // Port of the whole-alphabet UPER rows in go-asn1 f2c57b4 runtime/per/charstring_test.go.
// X.691 (02/2021) §30.5 supplies the independent expected bits.
type characterStringVector struct {
	name                    string
	lead, trail             bool
	bits                    int
	lb, ub                  int64
	constrained, extensible bool
	value, hex              string
}

var characterStringVectors = []characterStringVector{
	{name: "ENBname uper", bits: 7, lb: 1, ub: 150, constrained: true, extensible: true, value: "ab", hex: "00e1c4"},
	{name: "VisibleString uper", bits: 7, value: "http://x", hex: "08d1d3a7074bd7f8"},
	{name: "zero length uper", trail: true, bits: 7, lb: 0, ub: 4, constrained: true, value: "", hex: "10"},
}

func TestCharacterStringVectors(t *testing.T) {
	for _, v := range characterStringVectors {
		t.Run(v.name, func(t *testing.T) {
			want, err := hex.DecodeString(v.hex)
			if err != nil {
				t.Fatal(err)
			}
			writer := NewBitBuffer()
			if v.lead {
				if err := EncodeBoolean(writer, true); err != nil {
					t.Fatal(err)
				}
			}
			if err := EncodeKnownMultiplierStringExt(writer, v.value, v.bits, v.lb, v.ub, v.constrained, v.extensible); err != nil {
				t.Fatal(err)
			}
			if v.trail {
				if err := EncodeBoolean(writer, true); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(writer.CompleteBytes(), want) {
				t.Fatalf("wire %x want %x", writer.CompleteBytes(), want)
			}
			reader := NewBitBufferFromBytes(want)
			if v.lead {
				if b, err := DecodeBoolean(reader); err != nil || !b {
					t.Fatal(err)
				}
			}
			got, err := DecodeKnownMultiplierStringExt(reader, v.bits, v.lb, v.ub, v.constrained, v.extensible)
			if err != nil || got != v.value {
				t.Fatalf("decoded %q %v", got, err)
			}
			if v.trail {
				if b, err := DecodeBoolean(reader); err != nil || !b {
					t.Fatal(err)
				}
			}
			if err := ValidateFinalPadding(reader); err != nil {
				t.Fatal(err)
			}
		})
	}
}
