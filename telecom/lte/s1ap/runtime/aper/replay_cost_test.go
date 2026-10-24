// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_cost_test.go; SHA-256 852c5fb9aacada82df5b3a0c28fb49a5d7f74330bf2a6cd35777a121bd256b6d.
package aper

import (
	"errors"
	"testing"
)

// Locations own independent ranges of the complete decoder's reserved span
// storage. Overflow is still reserved before copying (X.691 (02/2021)
// §§11.2.1 and 11.9.3.8 define the fragmented content boundaries).
func TestContentLocationsUseReservedOwnerSlots(t *testing.T) {
	input := []byte{0xa5, 0x7e, 0x5a}
	data, state := StartDecode(input)
	parent := NewCompleteDecodeBuffer(data, state)
	if err := parent.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	image := WireSpan{original: data, segments: []BitSpan{{Start: 0, End: 8}, {Start: 16, End: 24}}}
	value := OpaqueOpenType{image: image, parent: parent}
	before := state.Usage()
	first, second := value.ContentLocation(), value.ContentLocation()
	after := state.Usage()
	if after.AllocatedBytes != before.AllocatedBytes || after.Work-before.Work != 64 {
		t.Fatalf("inline copies allocated=%d work=%d, want 0/64", after.AllocatedBytes-before.AllocatedBytes, after.Work-before.Work)
	}
	if len(first.Spans) != 2 || len(second.Spans) != 2 || cap(first.Spans) != len(first.Spans) || cap(second.Spans) != len(second.Spans) {
		t.Fatal("shared slot capacities")
	}
	first.Spans[0].Start = 7
	first.Spans = append(first.Spans, BitSpan{Start: 99, End: 100})
	if second.Spans[0].Start != 0 || second.Spans[1].Start != 16 || image.segments[0].Start != 0 {
		t.Fatal("location edit reached another copy or original")
	}
	for _, extra := range []uint64{31, 32, 33} {
		data, state := StartDecode(input, WithLimits(Limits{MaxAllocatedBytes: before.AllocatedBytes + extra}))
		parent := NewCompleteDecodeBuffer(data, state)
		if err := parent.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		image.original = data
		value := OpaqueOpenType{image: image, parent: parent}
		_ = value.ContentLocation()
		_ = value.ContentLocation()
		third := value.ContentLocation()
		_, err := FinishDecode(state, nil)
		if (extra < 32) != errors.Is(err, ErrLimit) {
			t.Fatalf("overflow bytes=%d err=%v", extra, err)
		}
		if err == nil && (len(third.Spans) != 2 || !third.HasWireLocation) {
			t.Fatal("overflow lost location")
		}
		if err != nil {
			var located *DecodeError
			if !errors.As(err, &located) || !located.Location.HasWireLocation {
				t.Fatal("overflow lost original location")
			}
		}
	}
}

// Comparing received semantics examines at most the saved snapshot octets.
// Reserve that scan once before walking; added in-memory content is extra work.
func TestComparisonReservesBaselineBeforeTraversal(t *testing.T) {
	payload := make([]byte, 256)
	capture := NewSemanticCapture(1024)
	var root Snapshot
	frame := capture.Begin()
	capture.Bytes(payload)
	capture.End(frame, &root, false)
	minimum := operationMetadataBytes + uint64(root.end-root.start)
	for _, limit := range []uint64{minimum - 1, minimum, minimum + 1} {
		budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: limit}))
		if err != nil {
			t.Fatal(err)
		}
		compare := NewSemanticComparison(root, budget)
		if (limit < minimum) != errors.Is(compare.Err(), ErrLimit) {
			t.Fatalf("reservation limit=%d minimum=%d err=%v", limit, minimum, compare.Err())
		}
		if compare.Err() != nil {
			continue
		}
		f := compare.Begin()
		compare.Bytes(payload)
		compare.End(f, root, false)
		plan := compare.Plan()
		if compare.Err() != nil || !plan.Unchanged(root) || compare.BudgetValue().usage.Work != minimum {
			t.Fatalf("comparison work=%d minimum=%d err=%v", compare.BudgetValue().usage.Work, minimum, compare.Err())
		}
	}
	for _, size := range []int{256, 512, 1024} {
		required := minimum + uint64(size-len(payload))
		for _, limit := range []uint64{required - 1, required, required + 1} {
			budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: limit}))
			if err != nil {
				t.Fatal(err)
			}
			compare := NewSemanticComparison(root, budget)
			f := compare.Begin()
			compare.Bytes(make([]byte, size))
			compare.End(f, root, false)
			result := compare.BudgetValue()
			if (limit < required) != errors.Is(compare.Err(), ErrLimit) {
				t.Fatalf("size=%d limit=%d minimum=%d err=%v", size, limit, required, compare.Err())
			}
			if compare.Err() == nil && result.usage.Work != required {
				t.Fatalf("size=%d work=%d minimum=%d", size, result.usage.Work, required)
			}
		}
	}
}

func TestComparisonChargesFramesAddedAfterDecode(t *testing.T) {
	capture := NewSemanticCapture(1024)
	var root Snapshot
	f := capture.Begin()
	capture.Uint(1)
	capture.End(f, &root, false)
	baseline := operationMetadataBytes + uint64(root.end-root.start)
	for _, count := range []int{16, 32, 64} {
		// The root's saved uint64 can be consumed as the first added frame
		// header. Every further absent frame and scalar needs its own work.
		required := baseline + uint64(count-1)*8 + uint64(count)*8
		for _, limit := range []uint64{required - 1, required, required + 1} {
			budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: limit}))
			if err != nil {
				t.Fatal(err)
			}
			compare := NewSemanticComparison(root, budget)
			frame := compare.Begin()
			for i := 0; i < count && compare.Err() == nil; i++ {
				child := compare.Begin()
				compare.Uint(1)
				compare.End(child, Snapshot{}, false)
			}
			compare.End(frame, root, false)
			result := compare.BudgetValue()
			if (limit < required) != errors.Is(compare.Err(), ErrLimit) {
				t.Fatalf("count=%d limit=%d minimum=%d err=%v", count, limit, required, compare.Err())
			}
			if compare.Err() == nil && result.usage.Work != required {
				t.Fatalf("count=%d work=%d minimum=%d", count, result.usage.Work, required)
			}
		}
	}
}

func TestComparisonChargesEnlargedOpaqueImages(t *testing.T) {
	capture := NewSemanticCapture(1024)
	var root Snapshot
	f := capture.Begin()
	capture.Opaque(NewOpaqueOpenType(make([]byte, 32)))
	capture.End(f, &root, false)
	for _, size := range []int{64, 128, 256} {
		baseline := operationMetadataBytes + uint64(root.end-root.start) + 1 // one open determinant
		required := baseline + uint64(size-32)
		for _, limit := range []uint64{required - 1, required, required + 1} {
			budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: limit}))
			if err != nil {
				t.Fatal(err)
			}
			compare := NewSemanticComparison(root, budget)
			frame := compare.Begin()
			compare.Opaque(OpaqueOpenType{image: OriginalWire(make([]byte, size))})
			compare.End(frame, root, false)
			result := compare.BudgetValue()
			if (limit < required) != errors.Is(compare.Err(), ErrLimit) {
				t.Fatalf("size=%d limit=%d minimum=%d err=%v", size, limit, required, compare.Err())
			}
			plan := compare.Plan()
			if compare.Err() == nil && (plan.Unchanged(root) || result.usage.Work != required) {
				t.Fatalf("size=%d work=%d minimum=%d", size, result.usage.Work, required)
			}
		}
	}
}

func TestComparisonUnmatchedEndCannotWeakenDepth(t *testing.T) {
	budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxDepth: 1}))
	if err != nil {
		t.Fatal(err)
	}
	compare := NewSemanticComparison(Snapshot{}, budget)
	compare.End(SemanticFrame{}, Snapshot{}, false)
	_ = compare.Begin()
	_ = compare.Begin()
	if !errors.Is(compare.Err(), ErrLimit) {
		t.Fatalf("unmatched end weakened depth: %v", compare.Err())
	}
}
