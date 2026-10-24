// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/limits_operation_test.go; SHA-256 105d6475a6e20a198e50f5c2c4be2cda17e7c5fdef09371ac635ae2d04ad8ce7.
package aper

import (
	"errors"
	"math"
	"testing"
)

func TestOperationalLimitsAtBoundary(t *testing.T) {
	type operation struct {
		name     string
		limits   func(uint64) Limits
		data     []byte
		run      func(*BitBuffer) error
		required uint64
	}
	fragment := append([]byte{0xc1}, make([]byte, 16384)...)
	fragment = append(fragment, 0)
	cases := []operation{
		{"input", func(n uint64) Limits { return Limits{MaxInputBytes: n} }, []byte{1, 2, 3}, func(*BitBuffer) error { return nil }, 3},
		{"work", func(n uint64) Limits { return Limits{MaxWork: n} }, []byte{0}, func(bb *BitBuffer) error { _, e := bb.ReadBits(3); return e }, operationMetadataBytes + 3},
		{"allocation", func(n uint64) Limits { return Limits{MaxAllocatedBytes: n} }, []byte{1, 2, 3}, func(bb *BitBuffer) error { _, e := bb.ReadBytes(3); return e }, operationMetadataBytes + 3},
		{"depth", func(n uint64) Limits { return Limits{MaxDepth: n} }, []byte{0}, func(bb *BitBuffer) error {
			for range 3 {
				if e := bb.EnterDecodeValue(); e != nil {
					return e
				}
			}
			return nil
		}, 3},
		{"elements", func(n uint64) Limits { return Limits{MaxElements: n} }, []byte{0}, func(bb *BitBuffer) error { return bb.ChargeElements(3) }, 3},
		{"open", func(n uint64) Limits { return Limits{MaxOpenTypeBytes: n} }, []byte{3, 1, 2, 3}, func(bb *BitBuffer) error { _, e := DecodeOpenTypeAligned(bb); return e }, 3},
		{"fragments", func(n uint64) Limits { return Limits{MaxFragments: n} }, fragment, func(bb *BitBuffer) error { _, e := DecodeOpenTypeAligned(bb); return e }, 2},
		{"reports", func(n uint64) Limits { return Limits{MaxReports: n} }, []byte{1, 1}, func(bb *BitBuffer) error {
			raw, e := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
			if e != nil {
				return e
			}
			for range 3 {
				if e = raw.Observe(UnknownIE); e != nil {
					return e
				}
			}
			return nil
		}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, limit := range []uint64{tc.required - 1, tc.required, tc.required + 1} {
				for range 2 {
					bb := NewBitBufferFromBytes(tc.data)
					settings := ApplyDecodeOptions(WithLimits(tc.limits(limit)))
					err := bb.SetDecodeOptionsAligned(settings)
					if err == nil {
						err = tc.run(bb)
					}
					_, err = FinishDecode(settings, err)
					if (limit < tc.required) != errors.Is(err, ErrLimit) {
						t.Fatalf("limit=%d required=%d err=%v", limit, tc.required, err)
					}
					if err != nil {
						var located *DecodeError
						if !errors.As(err, &located) || !located.Location.HasWireLocation {
							t.Fatalf("unlocated resource error: %v", err)
						}
					}
				}
			}
		})
	}
}

func TestInvalidOperationalLimitRejectedBeforeRead(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0xff})
	err := bb.SetDecodeOptionsAligned(ApplyDecodeOptions(WithLimits(Limits{MaxInputBytes: math.MaxUint64})))
	if !errors.Is(err, ErrInvalidOptions) || bb.BitPos() != 0 {
		t.Fatalf("err=%v bit=%d", err, bb.BitPos())
	}
}

func TestFragmentAccountingGrowsLinearly(t *testing.T) {
	var previousAllocation, previousWork uint64
	for _, size := range []int{65536, 131072, 262144} {
		writer := NewBitBuffer()
		if err := EncodeOpenTypeAligned(writer, make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		bb := NewBitBufferFromBytes(writer.CompleteBytes())
		if err := bb.SetDecodeOptionsAligned(ApplyDecodeOptions()); err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeOpenTypeAligned(bb); err != nil {
			t.Fatal(err)
		}
		budget := bb.decodeBudget()
		if previousAllocation != 0 && (budget.allocated > previousAllocation*3 || budget.usage.Work > previousWork*3) {
			t.Fatalf("nonlinear size=%d allocation=%d work=%d", size, budget.allocated, budget.usage.Work)
		}
		previousAllocation, previousWork = budget.allocated, budget.usage.Work
	}
}

func TestOutputLimitIsIndependentAndDirectional(t *testing.T) {
	for _, limit := range []uint64{2, 3, 4} {
		budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxOutputBytes: limit}))
		if err != nil {
			t.Fatal(err)
		}
		bb := NewBudgetBuffer(budget)
		err = bb.WriteBytes([]byte{1, 2, 3})
		if (limit < 3) != errors.Is(err, ErrLimit) {
			t.Fatalf("output limit=%d err=%v", limit, err)
		}
	}
	settings := ApplyDecodeOptions(WithLimits(Limits{MaxOutputBytes: math.MaxUint64}))
	bb := NewBitBufferFromBytes([]byte{1, 2, 3})
	if err := bb.SetDecodeOptionsAligned(settings); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBytes(3); err != nil {
		t.Fatalf("decode applied output ceiling: %v", err)
	}
	budget, err := ValidationBudget(WithValidationLimits(Limits{MaxOutputBytes: math.MaxUint64}))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewBudgetBuffer(budget).WriteBytes([]byte{1, 2, 3}); err != nil {
		t.Fatalf("validation applied output ceiling: %v", err)
	}
}

func TestOptionsAreValuesAndZeroLimitsRestoreDefaults(t *testing.T) {
	for _, run := range []func() error{
		func() error {
			budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxWork: 1}), WithEncodeLimits(Limits{}))
			if err != nil {
				return err
			}
			return NewBudgetBuffer(budget).WriteBits(3, 2)
		},
		func() error {
			budget, err := BuildBudget(WithBuildLimits(Limits{MaxWork: 1}), WithBuildLimits(Limits{}))
			if err != nil {
				return err
			}
			return NewBudgetBuffer(budget).WriteBits(3, 2)
		},
		func() error {
			budget, err := ValidationBudget(WithValidationLimits(Limits{MaxWork: 1}), WithValidationLimits(Limits{}))
			if err != nil {
				return err
			}
			return NewBudgetBuffer(budget).WriteBits(3, 2)
		},
	} {
		if err := run(); err != nil {
			t.Fatalf("zero fields must select defaults: %v", err)
		}
	}
	limits := Limits{MaxWork: operationMetadataBytes + 2}
	option := WithLimits(limits)
	limits.MaxWork = operationMetadataBytes + 1
	bb := NewBitBufferFromBytes([]byte{0})
	if err := bb.SetDecodeOptionsAligned(ApplyDecodeOptions(option)); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(2); err != nil {
		t.Fatal(err)
	}
}

// X.691 permits arbitrarily large INTEGER/extension indexes. The owned int64
// representation ceiling is operational; it must not claim invalid syntax.
func TestRepresentationCeilingsAreResourceLimits(t *testing.T) {
	for _, tc := range []struct {
		wire   []byte
		decode func(*BitBuffer) error
	}{
		{append([]byte{9, 1}, make([]byte, 8)...), func(bb *BitBuffer) error { _, e := DecodeUnconstrainedWholeNumberAligned(bb); return e }},
		{append([]byte{9, 1}, make([]byte, 8)...), func(bb *BitBuffer) error { _, e := DecodeSemiConstrainedWholeNumberAligned(bb, 0); return e }},
		{[]byte{0xc0, 8, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, func(bb *BitBuffer) error { _, e := DecodeEnumeratedAligned(bb, 2, true); return e }},
	} {
		err := tc.decode(NewBitBufferFromBytes(tc.wire))
		if !errors.Is(err, ErrLimit) || errors.Is(err, ErrSyntax) {
			t.Fatalf("representation limit classified as syntax: %v", err)
		}
	}
}

func TestOpaqueBuildersAndChoiceEncodingShareTheBudget(t *testing.T) {
	budget, err := BuildBudget(WithBuildLimits(Limits{MaxOpenTypeBytes: 3}))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte{1, 2, 3}
	raw, err := BuildOpaqueOpenType(input, budget)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 9
	if raw.Bytes()[0] != 1 {
		t.Fatal("opaque builder retained caller storage")
	}
	if _, err := BuildOpaqueOpenType([]byte{1, 2, 3, 4}, budget); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	budget, err = EncodeBudget(WithEncodeLimits(Limits{MaxOutputBytes: 3}))
	if err != nil {
		t.Fatal(err)
	}
	extension, err := NewChoiceExtension(0, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := extension.EncodeTo(NewBudgetBuffer(budget)); !errors.Is(err, ErrLimit) {
		t.Fatalf("choice framing escaped output ceiling: %v", err)
	}
	// A selected known value must not reset its parent's counters.
	state := ApplyDecodeOptions()
	parent := NewBitBufferFromBytes([]byte{1, 0})
	if err := parent.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	selected, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := selected.ChildDecodeBuffer()
	if child.Budget() != parent.Budget() {
		t.Fatal("selected value started a new operation")
	}
	if _, err := child.ReadBit(); err != nil {
		t.Fatal(err)
	}
	choiceChild := extension.ChildDecodeBuffer(parent)
	if choiceChild.Budget() != parent.Budget() {
		t.Fatal("choice child started another operation")
	}
	if _, err := choiceChild.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	if parent.Usage().Work != child.Usage().Work {
		t.Fatal("nested counters diverged")
	}
}

func TestWriterWorkCeilingCountsBitsAndCopies(t *testing.T) {
	// Two emitted bits, one byte of backing storage and one copied byte.
	const required = operationMetadataBytes + 4
	for _, limit := range []uint64{required - 1, required, required + 1} {
		budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxWork: limit}))
		if err != nil {
			t.Fatal(err)
		}
		bb := NewBudgetBuffer(budget)
		err = bb.WriteBits(3, 2)
		if (limit < required) != errors.Is(err, ErrLimit) {
			t.Fatalf("limit=%d usage=%+v err=%v", limit, bb.Usage(), err)
		}
		if err == nil && bb.Usage().Work != required {
			t.Fatalf("uncharged output work: %+v", bb.Usage())
		}
	}
}

func TestOverflowReservationsFailBeforeAllocation(t *testing.T) {
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	bb := NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(math.MaxUint64, 2); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if bb.Usage().AllocatedBytes != operationMetadataBytes {
		t.Fatal("overflow reserved storage")
	}
	budget, err = EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	bb = NewBudgetBuffer(budget)
	if err := bb.ChargeLocatedReport(Location{Spans: []BitSpan{{Start: 0, End: 0}}}, math.MaxUint64); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	if bb.Usage().Reports != 0 || bb.Usage().AllocatedBytes != operationMetadataBytes {
		t.Fatal("overflow published a report")
	}
}
