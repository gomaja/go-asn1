// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/edited_copy_test.go; SHA-256 0bd4d39a3e862f4be286ce2d21cb7344e616b0a34d02878f758104d82bb01cbe.
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
					wire, state := OwnDecodeInputOptions([]byte{2, 1, 0}, options...)
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
