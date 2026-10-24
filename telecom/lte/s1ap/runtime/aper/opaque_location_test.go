// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/opaque_location_test.go; SHA-256 cf22fc5828303a2ee91122f6509482ddbb0f1fc58a2acd6fc974a22bf2a1fca9.
package aper

import (
	"errors"
	"testing"
)

var _ = map[DecodeBudget]bool{}

func TestOpaqueNestedLocationUsesContiguousSource(t *testing.T) {
	inner := NewBitBuffer()
	if err := EncodeOpenTypeAligned(inner, []byte{0x12, 0x34}); err != nil {
		t.Fatal(err)
	}
	outer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(outer, inner.CompleteBytes()); err != nil {
		t.Fatal(err)
	}
	root := NewBitBufferFromBytes(outer.CompleteBytes())
	parent, err := DecodeOpaqueOpenTypeAligned(root, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := DecodeOpaqueOpenTypeAligned(parent.ChildDecodeBuffer(), UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	location := child.Origin().Location
	if !location.HasWireLocation || len(location.Spans) != 1 || location.Spans[0] != (BitSpan{Start: 8, End: 32}) {
		t.Fatalf("nested location = %+v", location)
	}
}

func TestOpaqueFragmentedParentMapsChildLocation(t *testing.T) {
	contents := make([]byte, 16384)
	contents[0], contents[1], contents[2] = 2, 0x12, 0x34
	outer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(outer, contents); err != nil {
		t.Fatal(err)
	}
	root := NewBitBufferFromBytes(outer.CompleteBytes())
	parent, err := DecodeOpaqueOpenTypeAligned(root, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := DecodeOpaqueOpenTypeAligned(parent.ChildDecodeBuffer(), UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	if location := child.Origin().Location; !location.HasWireLocation || len(location.Spans) != 1 || location.Spans[0] != (BitSpan{Start: 8, End: 32}) {
		t.Fatalf("fragmented child location = %+v", location)
	}
}

func TestOpaqueLocationCrossesFragmentDeterminant(t *testing.T) {
	contents := make([]byte, 16388)
	copy(contents[16380:], []byte{7, 1, 2, 3, 4, 5, 6, 7})
	outer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(outer, contents); err != nil {
		t.Fatal(err)
	}
	parent, err := DecodeOpaqueOpenTypeAligned(NewBitBufferFromBytes(outer.CompleteBytes()), UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	parentContents := parent.ContentLocation()
	if !parentContents.HasWireLocation || len(parentContents.Spans) != 2 || parentContents.Spans[0] != (BitSpan{Start: 8, End: 131080}) || parentContents.Spans[1] != (BitSpan{Start: 131088, End: 131120}) {
		t.Fatalf("fragmented content location = %+v", parentContents)
	}
	reader := parent.ChildDecodeBuffer()
	if _, err := reader.ReadBytes(16380); err != nil {
		t.Fatal(err)
	}
	child, err := DecodeOpaqueOpenTypeAligned(reader, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	location := child.Origin().Location
	want := []BitSpan{{Start: 131048, End: 131080}, {Start: 131088, End: 131120}}
	if !location.HasWireLocation || len(location.Spans) != len(want) {
		t.Fatalf("cross-fragment location = %+v", location)
	}
	for i := range want {
		if location.Spans[i] != want[i] {
			t.Fatalf("cross-fragment spans = %+v, want %+v", location.Spans, want)
		}
	}
}

func TestOpaqueLocationStorageGrowsLinearly(t *testing.T) {
	inner := NewBitBuffer()
	if err := EncodeOpenTypeAligned(inner, []byte{0x12}); err != nil {
		t.Fatal(err)
	}
	measure := func(count int) float64 {
		outer := NewBitBuffer()
		for range count {
			if err := EncodeOpenTypeAligned(outer, inner.CompleteBytes()); err != nil {
				t.Fatal(err)
			}
		}
		wire := outer.CompleteBytes()
		return testing.AllocsPerRun(20, func() {
			root := NewBitBufferFromBytes(wire)
			for range count {
				parent, err := DecodeOpaqueOpenTypeAligned(root, UnknownSelector, SourceRule{})
				if err != nil {
					panic(err)
				}
				if _, err := DecodeOpaqueOpenTypeAligned(parent.ChildDecodeBuffer(), UnknownSelector, SourceRule{}); err != nil {
					panic(err)
				}
			}
		})
	}
	small, large := measure(32), measure(128)
	if large > small*5 {
		t.Fatalf("opaque origin allocations grow too fast: 32=%g, 128=%g", small, large)
	}
}

func TestFragmentedOpaqueLocationStorageGrowsLinearly(t *testing.T) {
	measure := func(fragments int) float64 {
		contents := make([]byte, 16384*fragments)
		contents[0], contents[1] = 1, 0x5a
		outer := NewBitBuffer()
		if err := EncodeOpenTypeAligned(outer, contents); err != nil {
			t.Fatal(err)
		}
		wire := outer.CompleteBytes()
		return testing.AllocsPerRun(5, func() {
			parent, err := DecodeOpaqueOpenTypeAligned(NewBitBufferFromBytes(wire), UnknownSelector, SourceRule{})
			if err != nil {
				panic(err)
			}
			if _, err := DecodeOpaqueOpenTypeAligned(parent.ChildDecodeBuffer(), UnknownSelector, SourceRule{}); err != nil {
				panic(err)
			}
		})
	}
	small, large := measure(4), measure(16)
	if large > small*5+10 {
		t.Fatalf("fragmented opaque origin allocations grow too fast: 4=%g, 16=%g", small, large)
	}
}

func TestContiguousOpaqueLocationIsMaterializedOnDemand(t *testing.T) {
	wire := []byte{2, 0xa5, 0x5a}
	raw, err := DecodeOpaqueOpenTypeAligned(NewBitBufferFromBytes(wire), UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.payloadSegments) != 0 {
		t.Fatal("contiguous payload retained a redundant segment array")
	}
	wire[1] = 0
	if got := raw.Bytes(); len(got) != 2 || got[0] != 0xa5 {
		t.Fatalf("contents alias input: %x", got)
	}
	first := raw.ContentLocation()
	if !first.HasWireLocation || len(first.Spans) != 1 || first.Spans[0] != (BitSpan{Start: 8, End: 24}) {
		t.Fatalf("location=%+v", first)
	}
	first.Spans[0].Start = 999
	if got := raw.ContentLocation(); got.Spans[0].Start != 8 {
		t.Fatal("content locations share writable spans")
	}
	child := raw.ChildDecodeBuffer()
	spans, ok := originalRange(child, 0, 16)
	if !ok || len(spans) != 1 || spans[0] != (BitSpan{Start: 8, End: 24}) {
		t.Fatalf("child location=%+v", spans)
	}
}

func TestOpaqueLocationAllocationFailureIsReturned(t *testing.T) {
	for _, options := range [][]DecodeOption{nil, {WithReceiverMode()}} {
		for _, maximum := range []uint64{1024, 1025, 1026, 1040, 1041, 1042} {
			state := ApplyDecodeOptions(append(options, WithLimits(Limits{MaxAllocatedBytes: maximum}))...)
			bb := NewBitBufferFromBytes([]byte{1, 0})
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			value, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
			if maximum < 1041 {
				if !errors.Is(err, ErrLimit) || value.bytes != nil {
					t.Fatalf("limit=%d returned contents after failed location allocation: err=%v", maximum, err)
				}
			} else if err != nil || len(value.bytes) != 1 {
				t.Fatalf("limit=%d value=%+v err=%v", maximum, value, err)
			}
		}
	}
}
