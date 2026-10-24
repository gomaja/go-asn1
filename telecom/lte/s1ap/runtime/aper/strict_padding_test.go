// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/strict_padding_test.go; SHA-256 131aba4a5916f8584eac02ccf6b425f3c21e468e75d233fdc3dc3b3aec8bb5d8.
package aper

import (
	"errors"
	"testing"
)

// X.691 (02/2021) §11.1.4 requires every alignment and terminal bit to be zero;
// §11.2.1 makes the boundary of an embedded open value a complete encoding.
func TestStrictCompletePaddingAtEveryWidth(t *testing.T) {
	for _, capture := range []struct {
		name string
		run  func(*BitBuffer) (CompletePadding, error)
	}{{"top-level", CaptureFinalPadding}, {"open", CaptureOpenTypePadding}} {
		for used := 1; used < 8; used++ {
			for bit := 0; bit < 8-used; bit++ {
				bb := NewBitBufferFromBytes([]byte{byte(1 << bit)})
				if _, err := bb.ReadBits(used); err != nil {
					t.Fatal(err)
				}
				_, err := capture.run(bb)
				if !errors.Is(err, ErrInvalidValue) || !errors.Is(err, ErrSyntax) {
					t.Fatalf("%s used=%d bit=%d: %v", capture.name, used, bit, err)
				}
				var located *DecodeError
				if !errors.As(err, &located) || located.Rule.Clause != "§11.1.4" || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: uint64(used), End: 8}) {
					t.Fatalf("padding location/rule: %+v", located)
				}
			}
		}
	}
}

// X.691 (02/2021) §11.9.3.8 inserts length determinants between fragments.
// A joined open-value cursor must still identify terminal bits in original input.
func TestStrictFragmentedOpenPaddingLocation(t *testing.T) {
	contents := make([]byte, 16385)
	contents[len(contents)-1] = 1
	writer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(writer, contents); err != nil {
		t.Fatal(err)
	}
	wire := writer.CompleteBytes()
	raw, err := DecodeOpaqueOpenTypeAligned(NewBitBufferFromBytes(wire), UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	if _, err := child.ReadBytes(16384); err != nil {
		t.Fatal(err)
	}
	if _, err := child.ReadBit(); err != nil {
		t.Fatal(err)
	}
	_, err = CaptureOpenTypePadding(child)
	var located *DecodeError
	if !errors.As(err, &located) || !errors.Is(err, ErrSyntax) || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: uint64(len(wire)-1)*8 + 1, End: uint64(len(wire)) * 8}) {
		t.Fatalf("fragmented terminal location: %v, %+v", err, located)
	}
}

func TestStandaloneSelectedOpenPaddingLocation(t *testing.T) {
	raw, err := NewOpaqueOpenTypeWithState([]byte{1}, ApplyDecodeOptions())
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	if _, err := child.ReadBit(); err != nil {
		t.Fatal(err)
	}
	_, err = CaptureOpenTypePadding(child)
	var located *DecodeError
	if !errors.As(err, &located) || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: 1, End: 8}) {
		t.Fatalf("standalone selected value lost original location: %v, %+v", err, located)
	}
}

// Known addition decoders keep caller-owned cursors while preserving the
// original location across the fragments allowed by X.691 §11.9.3.8.
func TestCallerOwnedChildMapsCompleteContentLocation(t *testing.T) {
	for _, size := range []int{2, 16385} {
		contents := make([]byte, size)
		contents[len(contents)-1] = 1
		writer := NewBitBuffer()
		if err := EncodeOpenTypeAligned(writer, contents); err != nil {
			t.Fatal(err)
		}
		wire := writer.CompleteBytes()
		parent := NewBitBufferFromBytes(wire)
		raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
		if err != nil {
			t.Fatal(err)
		}
		data := raw.Bytes()
		child := NewNestedDecodeBuffer(data, parent)
		if err := child.MapOriginalLocation(data, raw.ContentLocation()); err != nil {
			t.Fatal(err)
		}
		if _, err := child.ReadBytes(size - 1); err != nil {
			t.Fatal(err)
		}
		if _, err := child.ReadBit(); err != nil {
			t.Fatal(err)
		}
		_, err = CaptureOpenTypePadding(child)
		var located *DecodeError
		if !errors.As(err, &located) || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: uint64(len(wire)-1)*8 + 1, End: uint64(len(wire)) * 8}) {
			t.Fatalf("size=%d err=%v location=%+v", size, err, located)
		}
	}
}
