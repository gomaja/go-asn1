// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/strict_padding_test.go; SHA-256 29084baf253ecf8df86b9861a601042b6a801df312f8cde2e510d1eeb3700038.
package aper

import (
	"errors"
	"reflect"
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

// X.691 (02/2021) §§11.1.4, 11.2.1, 11.9.3.8 and 23.8.
func TestCopiedChoicePaddingLocation(t *testing.T) {
	for _, size := range []int{1, 16385} {
		for _, empty := range []bool{false, true} {
			if empty && size != 1 {
				continue
			}
			payload := make([]byte, size)
			payload[size-1] = 255
			writer := NewBitBuffer()
			if err := EncodeOpenTypeAligned(writer, payload); err != nil {
				t.Fatal(err)
			}
			wire := writer.CompleteBytes()
			state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
			var budget DecodeBudget
			parent := NewDecodeBuffer(wire, &budget)
			if err := parent.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			data, err := DecodeOpenTypeAligned(parent)
			if err != nil {
				t.Fatal(err)
			}
			child := NewNestedDecodeBuffer(data, parent)
			consumed := (size - 1) * 8
			if !empty {
				consumed++
			}
			if err := skipChoiceBits(child, consumed); err != nil {
				t.Fatal(err)
			}
			if _, err := CaptureOpenTypePadding(child); err != nil {
				t.Fatal(err)
			}
			report, err := FinishDecode(state, nil)
			if err != nil {
				t.Fatal(err)
			}
			width := uint8(7)
			kind := NonzeroTerminalPadding
			value := uint8(127)
			if empty {
				width = 8
				kind = NonzeroEmptyEncoding
				value = 255
			}
			end := uint64(len(wire)) * 8
			want := DecodeReport{Observations: []Observation{{Kind: kind, PaddingBits: value, PaddingCount: width, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: Location{Path: "open type", Spans: []BitSpan{{Start: end - uint64(width), End: end}}, HasWireLocation: true}}}}
			if !reflect.DeepEqual(report, want) {
				t.Fatalf("size=%d empty=%v report=%+v want=%+v", size, empty, report, want)
			}
		}
	}
}
func skipChoiceBits(bb *BitBuffer, n int) error {
	for n > 0 {
		width := n
		if width > 64 {
			width = 64
		}
		if _, err := bb.ReadBits(width); err != nil {
			return err
		}
		n -= width
	}
	return nil
}

// A known source alternative read without a complete-value owner still has
// received provenance. X.691 (02/2021) §§11.2.1 and 23.8.
func TestKnownChoicePaddingWithoutOwner(t *testing.T) {
	for _, size := range []int{1, 16385} {
		payload := make([]byte, size)
		payload[size-1] = 255
		writer := NewBitBuffer()
		if err := EncodeOpenTypeAligned(writer, payload); err != nil {
			t.Fatal(err)
		}
		wire := writer.CompleteBytes()
		state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
		parent := NewBitBufferFromBytes(wire)
		if err := parent.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		extension, err := DecodeChoiceExtensionAligned(parent, 0)
		if err != nil {
			t.Fatal(err)
		}
		child := extension.ChildDecodeBuffer(parent)
		if err := skipChoiceBits(child, (size-1)*8+1); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureOpenTypePadding(child); err != nil {
			t.Fatal(err)
		}
		report, err := FinishDecode(state, nil)
		if err != nil {
			t.Fatal(err)
		}
		end := uint64(len(wire)) * 8
		want := DecodeReport{Observations: []Observation{{Kind: NonzeroTerminalPadding, PaddingBits: 127, PaddingCount: 7, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: Location{Path: "open type", Spans: []BitSpan{{Start: end - 7, End: end}}, HasWireLocation: true}}}}
		if !reflect.DeepEqual(report, want) {
			t.Fatalf("size=%d report=%+v want=%+v", size, report, want)
		}
	}
}

func TestOpaqueCopyPaddingLocation(t *testing.T) {
	for _, size := range []int{1, 16385} {
		for _, empty := range []bool{false, true} {
			if empty && size != 1 {
				continue
			}
			payload := make([]byte, size)
			payload[size-1] = 255
			writer := NewBitBuffer()
			if err := EncodeOpenTypeAligned(writer, payload); err != nil {
				t.Fatal(err)
			}
			wire := writer.CompleteBytes()
			state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
			var budget DecodeBudget
			parent := NewDecodeBuffer(wire, &budget)
			if err := parent.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
			data := raw.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			child := NewNestedDecodeBuffer(data, parent)
			consumed := (size - 1) * 8
			if !empty {
				consumed++
			}
			if err := skipChoiceBits(child, consumed); err != nil {
				t.Fatal(err)
			}
			if _, err := CaptureOpenTypePadding(child); err != nil {
				t.Fatal(err)
			}
			report, err := FinishDecode(state, nil)
			if err != nil {
				t.Fatal(err)
			}
			width := uint8(7)
			kind := NonzeroTerminalPadding
			value := uint8(127)
			if empty {
				width = 8
				kind = NonzeroEmptyEncoding
				value = 255
			}
			end := uint64(len(wire)) * 8
			want := DecodeReport{Observations: []Observation{{Kind: kind, PaddingBits: value, PaddingCount: width, Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: Location{Path: "open type", Spans: []BitSpan{{Start: end - uint64(width), End: end}}, HasWireLocation: true}}}}
			if !reflect.DeepEqual(report, want) {
				t.Fatalf("size=%d empty=%v report=%+v want=%+v", size, empty, report, want)
			}
		}
	}
}

func TestOpaquePaddingCopyPreservesAllocationFailure(t *testing.T) {
	state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
	parent := NewBitBufferFromBytes([]byte{1, 255})
	if err := parent.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	// Exhaust the remaining allocation allowance only after the received payload
	// and its provenance exist, so the accessor copy exercises its own charge.
	budget := parent.decodeBudget()
	budget.operational.MaxAllocatedBytes = budget.allocated
	if data := raw.Bytes(); data != nil {
		t.Fatalf("copy succeeded after exhausting allocation budget: %x", data)
	}
	if !errors.Is(budget.err, ErrLimit) {
		t.Fatalf("copy replaced allocation failure: %v", budget.err)
	}
}

func TestMappedOpenTypeFramingFailureKeepsRule(t *testing.T) {
	wire, state := StartDecode([]byte{0}, WithNonzeroTerminalPadding())
	bb := NewCompleteDecodeBuffer(wire, state)
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	_, err := DecodeOpenTypeAligned(bb)
	var located *DecodeError
	if !errors.Is(err, ErrInvalidValue) || !errors.As(err, &located) || located.Rule.Clause != "§11.2.1" || !located.Location.HasWireLocation {
		t.Fatalf("framing failure lost rule or source: %v %+v", err, located)
	}
}
