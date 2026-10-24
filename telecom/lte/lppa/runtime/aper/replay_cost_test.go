// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_cost_test.go; SHA-256 ecb76904db06a79209e65718612c8f52839051d8b48858eafbfc4ce5e82c20b7.
package aper

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

func TestComparisonFrameStackBudget(t *testing.T) {
	if size := unsafe.Sizeof(ComparisonFrame{}); size > 48 {
		t.Fatalf("comparison frame retains %d bytes, want at most 48", size)
	}
}

func TestOwnedContiguousInputNeedsNoOriginMap(t *testing.T) {
	input := []byte{0xff, 2, 0x12, 0x34, 0xff}
	owned, state := OwnDecodeInputOptions(input)
	parent := NewCompleteDecodeBuffer(owned, state)
	if _, err := parent.ReadBits(8); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	if got, err := child.ReadBits(16); err != nil || got != 0x1234 {
		t.Fatalf("child=%x err=%v", got, err)
	}
	span := child.CaptureWireSpan(0)
	if !bytes.Equal(span.Bytes(), []byte{0x12, 0x34}) {
		t.Fatalf("received bytes=%x", span.Bytes())
	}
	location := span.ContentLocation()
	if len(location.Spans) != 1 || location.Spans[0] != (BitSpan{Start: 16, End: 32}) {
		t.Fatalf("location=%+v", location)
	}
	if state.settings.operation.origin != nil {
		t.Fatal("unfragmented owned input allocated an origin map")
	}
}

func TestOwnedOpaqueMetadataAllocatesOnlyWhenNeeded(t *testing.T) {
	owned, state := OwnDecodeInputOptions(make([]byte, 15))
	bb := NewCompleteDecodeBuffer(owned, state)
	raw := NewOpaqueOpenType([]byte{1, 2, 3})
	raw.parent = bb
	owner := bb.Budget().owner
	slot := owner.opaque
	if slot == nil {
		t.Fatal("small owner has no opaque metadata slot")
	}
	if got := testing.AllocsPerRun(20, func() {
		owner.opaque = slot
		value, err := raw.Retained()
		if err != nil || value == nil || value.parent != nil {
			panic("opaque retention")
		}
	}); got != 0 {
		t.Fatalf("inline opaque metadata allocated %.0f times", got)
	}
	owner.opaque = slot
	first, err := raw.Retained()
	if err != nil {
		t.Fatal(err)
	}
	second, err := raw.Retained()
	if err != nil {
		t.Fatal(err)
	}
	*first = NewOpaqueOpenType([]byte{9})
	if first == second || !bytes.Equal(second.Bytes(), []byte{1, 2, 3}) {
		t.Fatal("retained opaque occurrences share mutable metadata")
	}
}

func TestUnchangedComparisonKeepsFailureAndFreshState(t *testing.T) {
	absent := NewSemanticComparison(Snapshot{})
	if absent.Unchanged(Snapshot{}) {
		t.Fatal("absent snapshot became replayable")
	}
	var root Snapshot
	capture := NewSemanticCapture(256)
	f := capture.Begin()
	capture.Uint(3)
	capture.End(f, &root, false)
	for _, row := range []struct {
		value                               uint64
		fresh, limited, sameRoot, unchanged bool
	}{
		{3, false, false, true, true},
		{4, false, false, true, false},
		{3, true, false, true, false},
		{3, false, true, true, false},
		{3, false, false, false, false},
	} {
		limits := ComparisonLimits{}
		if row.limited {
			limits = ComparisonLimits{Work: 9, limited: true}
		}
		comparison := NewSemanticComparison(root, limits)
		frame := comparison.Begin()
		comparison.Uint(row.value)
		if row.limited {
			comparison.Elements(1)
		}
		comparison.End(frame, root, row.fresh)
		candidate := root
		if !row.sameRoot {
			candidate = Snapshot{}
		}
		if got := comparison.Unchanged(candidate); got != row.unchanged {
			t.Fatalf("comparison %+v unchanged=%v", row, got)
		}
		budget, err := EncodeBudget()
		if err != nil {
			t.Fatal(err)
		}
		err = comparison.ChargeComparison(budget)
		if row.limited != errors.Is(err, ErrResourceLimit) {
			t.Fatalf("comparison %+v error=%v", row, err)
		}
	}
}

func TestSuccessfulFinishDecodeAllocatesNoDiagnosticState(t *testing.T) {
	state := ApplyDecodeOptions()
	if got := testing.AllocsPerRun(30, func() {
		report, err := FinishDecode(state, nil)
		if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 0 {
			panic("successful decode report")
		}
	}); got != 0 {
		t.Fatalf("successful finalization allocated %.0f times", got)
	}
}

func TestOwnedContiguousOriginsCheckBackingStorage(t *testing.T) {
	owned, state := OwnDecodeInputOptions([]byte{0xff, 0xff, 0x12, 0x34, 0xff})
	parent := NewCompleteDecodeBuffer(owned, state)
	foreign := make([]byte, len(owned), cap(owned))
	copy(foreign, owned)
	child := NewOwnedNestedDecodeBuffer(foreign, parent)
	if _, err := child.ReadBits(8); err != nil {
		t.Fatal(err)
	}
	if child.CaptureWireSpan(0).Present() {
		t.Fatal("foreign backing storage acquired an implicit original location")
	}
	// A full-slice expression changes capacity without changing source bytes.
	span := WireSpan{original: owned[:len(owned):len(owned)], start: 16, end: 32}
	child = span.decodeBuffer(parent)
	if _, err := child.ReadBits(16); err != nil {
		t.Fatal(err)
	}
	got := child.CaptureWireSpan(0)
	if !bytes.Equal(got.Bytes(), []byte{0x12, 0x34}) || got.start != 16 || got.end != 32 {
		t.Fatalf("capacity-limited original lost its source: %+v bytes=%x", got, got.Bytes())
	}
}

func TestOpaqueMetadataRespectsAllocationCeiling(t *testing.T) {
	budget, err := NewOperationBudget(Limits{MaxAllocatedBytes: operationMetadataBytes + uint64(unsafe.Sizeof(OpaqueOpenType{})) - 1})
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOpaqueOpenType([]byte{1}).Retained(budget)
	if value != nil || !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("opaque metadata escaped its ceiling: value=%v err=%v", value, err)
	}
}

func TestInlineSnapshotWritesChargeEveryCopiedOctet(t *testing.T) {
	_, state := OwnDecodeInputOptions([]byte{1})
	budget := state.settings.operation
	capture := SemanticCaptureFor(state)
	before := budget.usage.Work
	f := capture.Begin()
	capture.Uint(3)
	var root Snapshot
	capture.End(f, &root, false)
	want := uint64(len(root.owner.data)) + uint64(unsafe.Sizeof(replayResources{}))
	if got := budget.usage.Work - before; got != want {
		t.Fatalf("inline snapshot charged %d units for %d copied octets", got, want)
	}
	_, state = OwnDecodeInputOptions([]byte{1})
	budget = state.settings.operation
	budget.limits.MaxWork = int(budget.usage.Work + want - 1)
	capture = SemanticCaptureFor(state)
	f = capture.Begin()
	capture.Uint(3)
	capture.End(f, &root, false)
	if !capture.Failed() {
		t.Fatal("inline snapshot escaped the remaining work ceiling")
	}
}

func TestRetainedOpaqueCannotReplaceEnclosingBudget(t *testing.T) {
	foreign, err := NewOperationBudget(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, supplied := range []*DecodeBudget{nil, foreign} {
		parent, err := NewOperationBudget(Limits{MaxAllocatedBytes: operationMetadataBytes + uint64(unsafe.Sizeof(OpaqueOpenType{})) - 1})
		if err != nil {
			t.Fatal(err)
		}
		raw := NewOpaqueOpenType([]byte{1})
		raw.parent = NewBudgetBuffer(parent)
		value, err := raw.Retained(supplied)
		if value != nil || !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("opaque metadata replaced its enclosing budget: value=%v err=%v", value, err)
		}
	}
}
