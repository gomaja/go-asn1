// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/unmapped_padding_test.go; SHA-256 41c8512952f8b5af641bfadd354ed6fc3a28da86e21dc878f4b73c7bbd5b7d9c.
package aper

import (
	"bytes"
	"reflect"
	"testing"
)

// X.691 (02/2021) §§11.1.4 and 11.2.1 govern the complete payload;
// a caller's copy has no original-input coordinates to attach to its padding.
func TestUnmappedNestedOpenTypePadding(t *testing.T) {
	for _, receiver := range []bool{false, true} {
		for _, owned := range []bool{false, true} {
			for _, tolerate := range []bool{false, true} {
				for _, empty := range []bool{false, true} {
					options := []DecodeOption{}
					if receiver {
						options = append(options, WithReceiverMode())
					}
					if tolerate {
						options = append(options, WithNonzeroTerminalPadding())
					}
					wire, state := OwnDecodeInput([]byte{0}, ApplyDecodeOptions(options...))
					parent := NewCompleteDecodeBuffer(wire, state)
					if err := parent.SetDecodeOptionsAligned(state); err != nil {
						t.Fatal(err)
					}
					copied := []byte{1, 255}
					var nested *BitBuffer
					if owned {
						nested = NewOwnedNestedDecodeBuffer(copied, parent)
					} else {
						nested = NewNestedDecodeBuffer(copied, parent)
					}
					data, err := DecodeOpenTypeAligned(nested)
					if err != nil || !bytes.Equal(data, []byte{255}) {
						t.Fatalf("receiver=%v owned=%v tolerate=%v empty=%v: payload=%x err=%v", receiver, owned, tolerate, empty, data, err)
					}
					if nested.BitPos() != 16 {
						t.Fatalf("cursor=%d", nested.BitPos())
					}
					child := NewNestedDecodeBuffer(data, nested)
					if !empty {
						if _, err := child.ReadBit(); err != nil {
							t.Fatal(err)
						}
					}
					_, paddingErr := CaptureOpenTypePadding(child)
					if tolerate && paddingErr != nil {
						t.Fatal(paddingErr)
					}
					if !tolerate && paddingErr == nil {
						t.Fatal("strict padding accepted")
					}
					report, err := FinishDecode(state, nil)
					if err != nil {
						t.Fatal(err)
					}
					want := DecodeReport{}
					if tolerate {
						kind, bits, count := NonzeroTerminalPadding, uint8(127), uint8(7)
						if empty {
							kind, bits, count = NonzeroEmptyEncoding, 255, 8
						}
						want.Observations = []Observation{{Kind: kind, PaddingBits: bits, PaddingCount: count, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: Location{Path: "open type"}}}
					}
					if !reflect.DeepEqual(report, want) {
						t.Fatalf("report=%+v want=%+v", report, want)
					}
				}
			}
		}
	}
}
