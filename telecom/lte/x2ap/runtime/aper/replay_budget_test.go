// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_budget_test.go; SHA-256 52106b3711568639a0edfb567fec716dd215b03395651d2fdfd89c59c32fbd2e.
package aper

import (
	"errors"
	"testing"
	"unsafe"
)

// The generated visitors call these hooks at source value/list/open boundaries;
// pointer-presence frames do not increase the source-value depth.
func TestSemanticComparisonHonorsOperationCeilings(t *testing.T) {
	data := []byte{1, 2, 3}
	image := OriginalWire(data)
	capture := NewSemanticCapture(128)
	f := capture.Begin()
	capture.EnterValue()
	capture.EnterValue()
	capture.Elements(3)
	capture.Open(image)
	capture.Bytes(data)
	capture.LeaveValue()
	capture.LeaveValue()
	var root Snapshot
	capture.End(f, &root, false)
	for _, tc := range []struct {
		name   string
		limits Limits
		fail   bool
	}{{"default", Limits{}, false}, {"depth", Limits{MaxDepth: 1}, true}, {"elements", Limits{MaxElements: 2}, true}, {"open", Limits{MaxOpenTypeBytes: 2}, true}, {"work", Limits{MaxWork: 1030}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			budget, err := EncodeBudgetValue(WithEncodeLimits(tc.limits))
			if err != nil {
				t.Fatal(err)
			}
			comparison := NewSemanticComparison(root, budget)
			f := comparison.Begin()
			comparison.EnterValue()
			comparison.EnterValue()
			comparison.Elements(3)
			comparison.Open(image)
			comparison.Bytes(data)
			comparison.LeaveValue()
			comparison.LeaveValue()
			comparison.End(f, root, false)
			plan := comparison.Plan()
			if errors.Is(plan.Error(), ErrLimit) != tc.fail {
				t.Fatalf("plan=%v expected limit=%t", plan.Error(), tc.fail)
			}
			if !tc.fail {
				if !plan.Unchanged(root) {
					t.Fatal("exact comparison changed value")
				}
				var committed DecodeBudget
				if err := plan.CommitBudget(&committed); err != nil {
					t.Fatal(err)
				}
				if NewBudgetBuffer(&committed).Usage().Elements != 3 {
					t.Fatal("comparison did not account list elements")
				}
				encoded, err := image.EncodePlanBytes(plan)
				if err != nil || len(encoded) != 3 {
					t.Fatal("unchanged plan did not copy its result")
				}
			}
		})
	}
}
func TestSemanticCaptureReservesArenaBeforeGrowing(t *testing.T) {
	// The owner's inline storage can be smaller than the operation's fixed
	// reservation on 32-bit hosts. OwnDecodeInput charges the greater size.
	fixed := max(operationMetadataBytes, uint64(unsafe.Sizeof(smallDecodeOwner{})))
	wire, state := OwnDecodeOptions([]byte{0}, WithLimits(Limits{MaxAllocatedBytes: fixed + 129}))
	bb := NewCompleteDecodeBuffer(wire, state)
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	capture := SemanticCaptureFor(state)
	f := capture.Begin()
	capture.Bytes(make([]byte, 256))
	var root Snapshot
	capture.End(f, &root, false)
	if !capture.Failed() || cap(capture.owner.data) > 128 {
		t.Fatal("snapshot arena grew before reservation")
	}
	if _, err := FinishDecode(state, nil); !errors.Is(err, ErrLimit) {
		t.Fatal("capture limit was not published")
	}
}

func TestOwnDecodeInputFixedStorageBoundaries(t *testing.T) {
	for _, tc := range []struct {
		octets int
		owner  uint64
	}{
		{1, uint64(unsafe.Sizeof(smallDecodeOwner{}))},
		{9, uint64(unsafe.Sizeof(compactDecodeOwner{}))},
		{33, uint64(unsafe.Sizeof(mediumDecodeOwner{}))},
		{129, uint64(unsafe.Sizeof(messageDecodeOwner{}))},
	} {
		required := max(operationMetadataBytes, tc.owner) + uint64(tc.octets)
		t.Logf("input=%d owner=%d metadata=%d required=%d", tc.octets, tc.owner, operationMetadataBytes, required)
		for _, limit := range []uint64{required - 1, required, required + 1} {
			wire, state := OwnDecodeOptions(make([]byte, tc.octets), WithLimits(Limits{MaxAllocatedBytes: limit}))
			err := NewCompleteDecodeBuffer(wire, state).SetDecodeOptionsAligned(state)
			if errors.Is(err, ErrLimit) != (limit < required) {
				t.Fatalf("owner %d, limit %d, required %d: %v", tc.octets, limit, required, err)
			}
			if err == nil && state.Usage().AllocatedBytes != required {
				t.Fatalf("owner %d charged %d, want %d", tc.octets, state.Usage().AllocatedBytes, required)
			}
		}
	}
}
func TestSemanticComparisonOverflowReservesItsBitset(t *testing.T) {
	capture := NewSemanticCapture(128)
	outer := capture.Begin()
	nodes := make([]Snapshot, 600)
	for i := range nodes {
		f := capture.Begin()
		capture.Int(0)
		capture.End(f, &nodes[i], false)
	}
	var root Snapshot
	capture.End(outer, &root, false)
	budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxAllocatedBytes: 1024}))
	if err != nil {
		t.Fatal(err)
	}
	comparison := NewSemanticComparison(root, budget)
	outer = comparison.Begin()
	for i, node := range nodes {
		f := comparison.Begin()
		n := int64(0)
		if i == len(nodes)-1 {
			n = 1
		}
		comparison.Int(n)
		comparison.End(f, node, false)
	}
	comparison.End(outer, root, false)
	plan := comparison.Plan()
	if !errors.Is(plan.Error(), ErrLimit) || plan.extra != nil {
		t.Fatal("overflow bitset allocated before reservation")
	}
}
func TestCompleteReceivedSpanFormKeepsPadding(t *testing.T) {
	f := NewCompleteReceivedSpanForm(true, OriginalWire([]byte{0x80}), "Value", true, CompletePadding{bits: 0, count: 7})
	if !f.Present() || len(f.OriginalBytes()) != 1 || len(f.Padding()) != 1 || f.Padding()[0].Span != (BitSpan{Start: 1, End: 8}) {
		t.Fatal("complete received span lost padding")
	}
}

func TestEncodeBudgetValueKeepsUnchangedStateOnStack(t *testing.T) {
	allocations := testing.AllocsPerRun(100, func() {
		budget, err := EncodeBudgetValue()
		if err != nil || budget.allocated != operationMetadataBytes || !budget.outputLimited {
			panic("invalid encode accounting")
		}
	})
	if allocations != 0 {
		t.Fatalf("by-value encode state allocated %v", allocations)
	}
	if _, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxAllocatedBytes: 1})); err == nil {
		t.Fatal("encode state ignored allocation ceiling")
	}
}
