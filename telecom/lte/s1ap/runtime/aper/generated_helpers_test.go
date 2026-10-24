// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/generated_helpers_test.go; SHA-256 3f2df5b3e1c54d5819f6ace0070aa09727bbf2af3e04edb6d89797aeff5a8a05.
package aper

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"unsafe"
)

func TestStartDecodeOwnsAndReservesInput(t *testing.T) {
	for _, size := range []int{8, 9, 65} {
		input := bytes.Repeat([]byte{0xa5}, size)
		fixed := uint64(unsafe.Sizeof(smallDecodeOwner{}))
		if size > 8 {
			fixed = uint64(unsafe.Sizeof(messageDecodeOwner{}))
		}
		required := max(operationMetadataBytes, fixed) + uint64(size)
		for _, limit := range []uint64{required - 1, required, required + 1} {
			owned, state := StartDecode(input, WithLimits(Limits{MaxAllocatedBytes: limit}))
			_, err := FinishDecode(state, nil)
			if (limit < required) != errors.Is(err, ErrLimit) {
				t.Fatalf("size=%d limit=%d need=%d err=%v", size, limit, required, err)
			}
			if err != nil {
				if owned != nil {
					t.Fatal("failed decode allocated input")
				}
				continue
			}
			if !bytes.Equal(owned, input) || state.Usage().AllocatedBytes != required || state.Usage().Work != required {
				t.Fatalf("ownership/accounting=%+v", state.Usage())
			}
			input[0] ^= 0xff
			if owned[0] == input[0] {
				t.Fatal("owned input aliases caller")
			}
			input[0] ^= 0xff
		}
		for _, limit := range []uint64{required - 1, required, required + 1} {
			_, state := StartDecode(input, WithLimits(Limits{MaxWork: limit}))
			_, err := FinishDecode(state, nil)
			if (limit < required) != errors.Is(err, ErrLimit) {
				t.Fatalf("work=%d need=%d err=%v", limit, required, err)
			}
		}
		_, state := StartDecode(input, WithLimits(Limits{MaxInputBytes: uint64(size - 1)}))
		if _, err := FinishDecode(state, nil); !errors.Is(err, ErrLimit) {
			t.Fatalf("input ceiling=%v", err)
		}
	}
	if _, state := StartDecode(nil, WithLimits(Limits{MaxWork: math.MaxUint64})); !errors.Is(state.failure, ErrInvalidOptions) {
		t.Fatalf("invalid limit=%v", state.failure)
	}
}

func TestReceivedCopiesReserveAndOwnTheirResults(t *testing.T) {
	input := []byte{0xa5, 0x7e, 0x5a}
	span := WireSpan{original: input, segments: []BitSpan{{Start: 0, End: 8}, {Start: 16, End: 24}}}
	for name, copyValue := range map[string]func(*DecodeBudget) ([]byte, error){
		"wire":   func(b *DecodeBudget) ([]byte, error) { return CopyReplay(span, b) },
		"image":  func(b *DecodeBudget) ([]byte, error) { return CopyOpaque(OpaqueOpenType{image: span}, b) },
		"caller": func(b *DecodeBudget) ([]byte, error) { return CopyOpaque(NewOpaqueOpenType([]byte{0xa5, 0x5a}), b) },
	} {
		t.Run(name, func(t *testing.T) {
			for _, limit := range []uint64{1, 2, 3} {
				b, err := EncodeBudget(WithEncodeLimits(Limits{MaxOutputBytes: limit}))
				if err != nil {
					t.Fatal(err)
				}
				got, err := copyValue(b)
				if (limit < 2) != errors.Is(err, ErrLimit) {
					t.Fatalf("output=%d err=%v", limit, err)
				}
				if err == nil {
					if !bytes.Equal(got, []byte{0xa5, 0x5a}) || b.allocated != operationMetadataBytes+2 || b.usage.Work != operationMetadataBytes+2 {
						t.Fatalf("copy=%x allocated=%d work=%d", got, b.allocated, b.usage.Work)
					}
					got[0] = 0
					again, err := copyValue(b)
					if err != nil || again[0] != 0xa5 || input[0] != 0xa5 {
						t.Fatal("copy aliases original")
					}
				}
				b, err = EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: operationMetadataBytes + limit}))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = copyValue(b); (limit < 2) != errors.Is(err, ErrLimit) {
					t.Fatalf("allocation=%d err=%v", limit, err)
				}
			}
		})
	}
}

func TestEncodeBudgetValueOptionsAndIsolation(t *testing.T) {
	option := WithEncodeLimits(Limits{MaxOutputBytes: 2, MaxAllocatedBytes: operationMetadataBytes + 2})
	a, err := EncodeBudgetValue(option)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeBudgetValue(option)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewBudgetBuffer(&a).WriteBytes([]byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if a.allocated != operationMetadataBytes+2 || b.allocated != operationMetadataBytes || b.usage.Work != operationMetadataBytes {
		t.Fatal("value budgets share counters")
	}
	if err := NewBudgetBuffer(&b).WriteBytes([]byte{1, 2, 3}); !errors.Is(err, ErrLimit) {
		t.Fatalf("option ignored: %v", err)
	}
	if _, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: 1})); !errors.Is(err, ErrLimit) {
		t.Fatalf("metadata ceiling=%v", err)
	}
	if _, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: math.MaxUint64})); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid options=%v", err)
	}
	c, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxWork: 1}), WithEncodeLimits(Limits{}))
	if err != nil || c.operational != DefaultLimits() {
		t.Fatalf("last option/defaults=%+v %v", c.operational, err)
	}
}

func TestCaptureOnlyChargesSemanticWork(t *testing.T) {
	_, state := StartDecode([]byte{0})
	capture := SemanticCaptureFor(state)
	before := state.Usage()
	data := append([]byte(nil), capture.owner.data...)
	// These checks are encode-only. Capture must not duplicate wire/framing work.
	capture.CheckReceived(Snapshot{}, OriginalWire([]byte{0xa5}))
	capture.CheckChoice(Snapshot{}, OriginalWire([]byte{0x80, 1, 0xa5}))
	if state.Usage() != before || !bytes.Equal(data, capture.owner.data) {
		t.Fatal("capture checks changed state")
	}
	capture.Elements(3)
	if capture.Err() != nil || state.Usage().Work != before.Work+3 || state.Usage().Elements != 0 {
		t.Fatalf("capture element work=%+v %v", state.Usage(), capture.Err())
	}
	_, state = StartDecode([]byte{0}, WithLimits(Limits{MaxWork: before.Work + 2}))
	capture = SemanticCaptureFor(state)
	capture.Elements(3)
	if !errors.Is(capture.Err(), ErrLimit) {
		t.Fatalf("capture ignored work ceiling: %v", capture.Err())
	}
}

func TestComparisonElementsShareCountersAndLimits(t *testing.T) {
	for _, limit := range []uint64{2, 3, 4} {
		budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxElements: limit}))
		if err != nil {
			t.Fatal(err)
		}
		compare := NewSemanticComparison(Snapshot{}, budget)
		compare.Elements(3)
		if (limit < 3) != errors.Is(compare.Err(), ErrLimit) {
			t.Fatalf("elements=%d err=%v", limit, compare.Err())
		}
		result := compare.BudgetValue()
		if limit >= 3 && (result.usage.Elements != 3 || result.usage.Work != operationMetadataBytes+3) {
			t.Fatalf("settled usage=%+v", result.usage)
		}
		if budget.usage.Elements != 0 {
			t.Fatal("comparison changed caller's by-value budget")
		}
	}
	compare := NewSemanticComparison(Snapshot{})
	compare.Elements(3)
	if compare.Err() != nil {
		t.Fatal(compare.Err())
	}
}

func TestReceivedChecksChargeOnlyUnchangedNodes(t *testing.T) {
	capture := NewSemanticCapture(256)
	var root Snapshot
	frame := capture.Begin()
	capture.End(frame, &root, false)
	span := OriginalWire(make([]byte, 65537))
	for _, changed := range []bool{false, true} {
		budget, err := EncodeBudgetValue(WithEncodeLimits(Limits{MaxFragments: 1}))
		if err != nil {
			t.Fatal(err)
		}
		compare := NewSemanticComparison(root, budget)
		if changed {
			compare.plan.markChanged(root.node)
		}
		compare.CheckReceived(root, span)
		if !changed != errors.Is(compare.Err(), ErrLimit) {
			t.Fatalf("changed=%t err=%v", changed, compare.Err())
		}
		result := compare.BudgetValue()
		if changed && result.fragments != 0 {
			t.Fatal("changed field charged retained framing")
		}
	}
	budget, err := EncodeBudgetValue()
	if err != nil {
		t.Fatal(err)
	}
	compare := NewSemanticComparison(root, budget)
	compare.CheckReceived(root, span)
	result := compare.BudgetValue()
	if compare.Err() != nil || result.fragments != 2 || result.usage.Work != operationMetadataBytes+uint64(root.end-root.start)+2 {
		t.Fatalf("retained fragments=%d work=%d err=%v", result.fragments, result.usage.Work, compare.Err())
	}
	budget, err = EncodeBudgetValue(WithEncodeLimits(Limits{MaxOpenTypeBytes: 65536}))
	if err != nil {
		t.Fatal(err)
	}
	compare = NewSemanticComparison(root, budget)
	compare.CheckReceived(root, span)
	if !errors.Is(compare.Err(), ErrLimit) {
		t.Fatal("retained open type escaped ceiling")
	}
}

// X.691 (02/2021) §§11.9.3.8 and 23.8: replay includes each retained
// CHOICE open determinant, in its original alignment and physical spans.
func TestChoiceChecksChargeReceivedFraming(t *testing.T) {
	capture := NewSemanticCapture(256)
	var root Snapshot
	frame := capture.Begin()
	capture.End(frame, &root, false)
	for _, size := range []int{1, 128, 65537} {
		for _, index := range []int64{1, 64} {
			w := NewBitBuffer()
			if err := EncodeBoolean(w, true); err != nil {
				t.Fatal(err)
			}
			if err := EncodeNormallySmallNonNegativeAligned(w, index); err != nil {
				t.Fatal(err)
			}
			if err := EncodeOpenTypeAligned(w, bytes.Repeat([]byte{0xa5}, size)); err != nil {
				t.Fatal(err)
			}
			wire := w.CompleteBytes()
			// Retain the same stream in two physical spans separated by an octet.
			physical := append(append(append([]byte(nil), wire[:2]...), 0x7e), wire[2:]...)
			span := WireSpan{original: physical, segments: []BitSpan{{Start: 0, End: 16}, {Start: 24, End: uint64(len(physical)) * 8}}}
			required := uint64(1)
			if size > 65536 {
				required = 2
			}
			budget, err := EncodeBudgetValue()
			if err != nil {
				t.Fatal(err)
			}
			compare := NewSemanticComparison(root, budget)
			compare.CheckChoice(root, span)
			result := compare.BudgetValue()
			if compare.Err() != nil || result.fragments != required || result.usage.Work != operationMetadataBytes+uint64(root.end-root.start)+required {
				t.Fatalf("size=%d index=%d fragments=%d err=%v", size, index, result.fragments, compare.Err())
			}
			if size > 1 {
				budget, err = EncodeBudgetValue(WithEncodeLimits(Limits{MaxOpenTypeBytes: uint64(size - 1)}))
				if err != nil {
					t.Fatal(err)
				}
				compare = NewSemanticComparison(root, budget)
				compare.CheckChoice(root, span)
				if !errors.Is(compare.Err(), ErrLimit) {
					t.Fatalf("size %d ignored open ceiling", size)
				}
			}
			if required > 1 {
				budget, err = EncodeBudgetValue(WithEncodeLimits(Limits{MaxFragments: 1}))
				if err != nil {
					t.Fatal(err)
				}
				compare = NewSemanticComparison(root, budget)
				compare.CheckChoice(root, span)
				if !errors.Is(compare.Err(), ErrLimit) {
					t.Fatal("choice ignored fragment ceiling")
				}
			}
		}
	}
	budget, err := EncodeBudgetValue()
	if err != nil {
		t.Fatal(err)
	}
	compare := NewSemanticComparison(root, budget)
	compare.CheckChoice(root, OriginalWire([]byte{0}))
	if compare.Err() != nil || compare.BudgetValue().fragments != 0 {
		t.Fatal("root alternative charged extension")
	}
	compare = NewSemanticComparison(root, budget)
	compare.plan.markChanged(root.node)
	compare.CheckChoice(root, OriginalWire([]byte{0x80}))
	if compare.Err() != nil || compare.BudgetValue().fragments != 0 {
		t.Fatal("changed choice inspected stale framing")
	}
	compare = NewSemanticComparison(root, budget)
	compare.CheckChoice(root, OriginalWire([]byte{0x80}))
	if !errors.Is(compare.Err(), ErrLimit) {
		t.Fatal("invalid internal retained framing passed")
	}
}
