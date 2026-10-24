// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/received_budget_regression_test.go; SHA-256 1f1d057daccbc5e9e6fc1157f0bda77edcc2ae890642e517d17499834102b526.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestStandaloneWriterKeepsLargeCopyBehaviour(t *testing.T) {
	for _, size := range []int{9 << 20, 17 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, size)
			bb := NewBitBuffer()
			if err := bb.WriteBytes(payload); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.Bytes(), payload) {
				t.Fatal("standalone writer changed contents")
			}
		})
	}
}

func TestSegmentedSpanCopiesWithoutIndependentCeiling(t *testing.T) {
	for _, size := range []int{8 << 20, 9 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			original := bytes.Repeat([]byte{0xa5}, size+1)
			original[size/2] = 0x7e
			span := WireSpan{original: original, segments: []BitSpan{{Start: 0, End: uint64(size/2) * 8}, {Start: uint64(size/2+1) * 8, End: uint64(size+1) * 8}}}
			want := bytes.Repeat([]byte{0xa5}, size)
			for name, copy := range map[string]func() []byte{"span": span.Bytes, "opaque": (OpaqueOpenType{image: span}).Bytes, "choice": (ChoiceExtension{image: span}).Contents, "received": (ReceivedForm{image: span}).OriginalBytes} {
				if got := copy(); !bytes.Equal(got, want) {
					t.Errorf("%s: copied %d bytes, want %d", name, len(got), size)
				}
			}
		})
	}
}

func TestReceivedCopyErrorsReachEncoders(t *testing.T) {
	// A corrupt internal span must never become successful empty open contents.
	invalid := WireSpan{original: []byte{1}, segments: []BitSpan{{Start: 0, End: 8}, {Start: 16, End: 24}}}
	for name, run := range map[string]func() error{
		"replay": func() error { budget, _ := EncodeBudget(); _, err := CopyReplay(invalid, budget); return err },
		"opaque": func() error {
			budget, _ := EncodeBudget()
			_, err := CopyOpaque(OpaqueOpenType{image: invalid}, budget)
			return err
		},
		"choice": func() error { return (ChoiceExtension{image: invalid}).EncodeTo(NewBitBuffer()) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("copy failure discarded: %v", err)
			}
		})
	}
}

// Complete values and their content locations obey X.691 (02/2021)
// §§11.2.1 and 11.9.3.8; every copied BitSpan belongs to the parent budget.
func TestOwnedOpenLocationCopiesAreReserved(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 65540)
	w := NewBitBuffer()
	if err := EncodeOpenTypeAligned(w, payload); err != nil {
		t.Fatal(err)
	}
	wire := w.Bytes()
	decode := func(limit uint64) (uint64, error) {
		data, state := StartDecode(wire, WithLimits(Limits{MaxAllocatedBytes: limit}))
		bb := NewCompleteDecodeBuffer(data, state)
		err := bb.SetDecodeOptionsAligned(state)
		if err == nil {
			_, err = DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
		}
		_, err = FinishDecode(state, err)
		return state.Usage().AllocatedBytes, err
	}
	// No variable source map is needed for the contiguous outer input. The
	// framed location uses an independent slot already reserved with the owner.
	data, state := StartDecode(wire)
	bb := NewCompleteDecodeBuffer(data, state)
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	before := state.Usage().AllocatedBytes
	raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	if got := state.Usage().AllocatedBytes - before; got != 0 {
		t.Fatalf("framed location overflow reservation=%d, want 0", got)
	}
	required := state.Usage().AllocatedBytes
	for _, limit := range []uint64{required - 1, required, required + 1} {
		_, err := decode(limit)
		if (limit < required) != errors.Is(err, ErrLimit) {
			t.Fatalf("framed location limit=%d required=%d error=%v", limit, required, err)
		}
		if err != nil {
			var located *DecodeError
			if !errors.As(err, &located) || !located.Location.HasWireLocation {
				t.Fatalf("unlocated: %v", err)
			}
		}
	}
	if len(raw.ContentLocation().Spans) != 2 {
		t.Fatal("fragmented content lost its spans")
	}
}

func TestImageBackedContentLocationCopyIsReserved(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 65540)
	w := NewBitBuffer()
	if err := EncodeOpenTypeAligned(w, payload); err != nil {
		t.Fatal(err)
	}
	wire := w.Bytes()
	data, state := StartDecode(wire)
	bb := NewCompleteDecodeBuffer(data, state)
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	value, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	// The framed span and the first two content spans occupy three of the
	// owner's four slots. A second two-span copy must reserve overflow.
	_ = value.ContentLocation()
	required := state.Usage().AllocatedBytes

	// The image-backed branch copies both physical content spans. Reserve
	// before copying even though ContentLocation's signature has no error.
	for _, extra := range []uint64{31, 32, 33} {
		data, state := StartDecode(wire, WithLimits(Limits{MaxAllocatedBytes: required + extra}))
		bb := NewCompleteDecodeBuffer(data, state)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		value, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
		if err != nil {
			t.Fatal(err)
		}
		_ = value.ContentLocation()
		location := value.ContentLocation()
		_, err = FinishDecode(state, nil)
		if (extra < 32) != errors.Is(err, ErrLimit) {
			t.Fatalf("content extra=%d err=%v", extra, err)
		}
		if err == nil && (len(location.Spans) != 2 || !location.HasWireLocation) {
			t.Fatalf("location=%+v", location)
		}
	}
}

func TestExtensionContentCopiesShareTheEncodeBudget(t *testing.T) {
	image := OriginalWire([]byte{0xa5, 0x5a})
	for _, limit := range []uint64{operationMetadataBytes, operationMetadataBytes + 1} {
		budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: limit}))
		if err != nil {
			t.Fatal(err)
		}
		if err := (ChoiceExtension{image: image}).EncodeTo(NewBudgetBuffer(budget)); !errors.Is(err, ErrLimit) {
			t.Fatalf("choice copy escaped allocation budget: %v", err)
		}
		budget, err = EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: limit}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CopyExtensionContents(nil, []WireSpan{image}, budget); !errors.Is(err, ErrLimit) {
			t.Fatalf("sequence copy escaped allocation budget: %v", err)
		}
	}
	invalid := WireSpan{original: []byte{1}, segments: []BitSpan{{Start: 0, End: 8}, {Start: 16, End: 24}}}
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CopyExtensionContents(nil, []WireSpan{invalid}, budget); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("sequence copy discarded error: %v", err)
	}
	budget, err = EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := CopyExtensionContents([][]byte{nil, {0x80}}, []WireSpan{image}, budget)
	if err != nil || !bytes.Equal(contents[0], image.Bytes()) || !bytes.Equal(contents[1], []byte{0x80}) {
		t.Fatalf("contents=%x error=%v", contents, err)
	}
}

func TestCursorlessDecodeReservationHasConsumedWireLocation(t *testing.T) {
	data, state := StartDecode([]byte{0x80})
	root := NewCompleteDecodeBuffer(data, state)
	if err := root.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	if _, err := root.ReadBits(8); err != nil {
		t.Fatal(err)
	}
	err := DecodeBuffer(state).ChargeAllocation(DefaultLimits().MaxAllocatedBytes, 1)
	var located *DecodeError
	if !errors.Is(err, ErrLimit) || !errors.As(err, &located) || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: 8, End: 8}) {
		t.Fatalf("cursorless decode reservation lost consumed boundary: %v location=%+v", err, located)
	}
}
