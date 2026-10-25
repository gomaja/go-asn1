// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/edited_copy_test.go; SHA-256 77973e6d5b1bf307e7277c81a5fb640bc05f290ce493461521ab1cc37e00ce27.
package aper

import (
	"bytes"
	"fmt"
	"testing"
)

// Accessor copies are mutable values, independent of the owned input image.
func TestEditedOpenTypeCopyUsesCurrentContents(t *testing.T) {
	for _, receiver := range []bool{false, true} {
		for _, padding := range []bool{false, true} {
			for _, opaque := range []bool{false, true} {
				t.Run(fmt.Sprintf("receiver=%t/padding=%t/opaque=%t", receiver, padding, opaque), func(t *testing.T) {
					var options []DecodeOption
					if receiver {
						options = append(options, WithReceiverMode())
					}
					if padding {
						options = append(options, WithNonzeroTerminalPadding())
					}
					wire, state := OwnDecodeInput([]byte{2, 1, 0}, ApplyDecodeOptions(options...))
					parent := NewCompleteDecodeBuffer(wire, state)
					if err := parent.SetDecodeOptionsAligned(state); err != nil {
						t.Fatal(err)
					}
					var copied []byte
					if opaque {
						raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
						if err != nil {
							t.Fatal(err)
						}
						copied = raw.Bytes()
					} else {
						var err error
						copied, err = DecodeOpenTypeAligned(parent)
						if err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(copied, []byte{1, 0}) {
						t.Fatalf("copy=%x", copied)
					}
					copied[1] = 42
					child := NewNestedDecodeBuffer(copied, parent)
					got, err := DecodeOpenTypeAligned(child)
					if err != nil || !bytes.Equal(got, []byte{42}) {
						t.Fatalf("edited copy decoded as %x: %v", got, err)
					}
					if !bytes.Equal(wire, []byte{2, 1, 0}) {
						t.Fatalf("copy edited original input: %x", wire)
					}
					if padding {
						paddingChild := NewNestedDecodeBuffer(copied, parent)
						if _, err := paddingChild.ReadBits(9); err != nil {
							t.Fatal(err)
						}
						if _, err := CaptureOpenTypePadding(paddingChild); err != nil {
							t.Fatal(err)
						}
					}
					report, err := FinishDecode(state, nil)
					if err != nil {
						t.Fatal(err)
					}
					if padding && (len(report.Observations) != 1 || report.Observations[0].PaddingBits != 42 || report.Observations[0].Location.HasWireLocation || len(report.Observations[0].Location.Spans) != 0) {
						t.Fatalf("edited copy claimed original padding: %+v", report)
					}
				})
			}
		}
	}
}
