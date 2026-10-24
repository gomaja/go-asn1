// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/image_encode_budget_test.go; SHA-256 1b47c6f88936fb89496c78deb1f527d590c70fcfb9ffd60166e5f9e131173197.
package aper

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
)

func TestImageChoiceEncodingChecksBudgetBeforeContentCopy(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 65540)
	writer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(writer, payload); err != nil {
		t.Fatal(err)
	}
	wire, state := OwnDecodeOptions(writer.CompleteBytes())
	parent := NewCompleteDecodeBuffer(wire, state)
	if err := parent.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	value, err := DecodeChoiceExtensionAligned(parent, 3)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	out := NewBudgetBuffer(budget)
	if err := value.EncodeTo(out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.CompleteBytes(), writer.CompleteBytes()) {
		t.Fatal("fragmented image framing changed")
	}
	budget, err = EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: 1025}))
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = value.EncodeTo(NewBudgetBuffer(budget))
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrLimit) || after.TotalAlloc-before.TotalAlloc > 16<<10 {
		t.Fatalf("copy preceded reservation: allocated=%d err=%v", after.TotalAlloc-before.TotalAlloc, err)
	}
}

func TestImageSequenceExtensionStreamsUnderBudget(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 65540)
	writer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(writer, payload); err != nil {
		t.Fatal(err)
	}
	wire, state := OwnDecodeOptions(writer.CompleteBytes())
	parent := NewCompleteDecodeBuffer(wire, state)
	if err := parent.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	spans := []WireSpan{raw.image}
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	out := NewBudgetBuffer(budget)
	if err := EncodeExtensionContents(out, nil, spans, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.CompleteBytes(), writer.CompleteBytes()) {
		t.Fatal("streamed sequence image differs")
	}
	budget, err = EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: 1025}))
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = EncodeExtensionContents(NewBudgetBuffer(budget), nil, spans, 0)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrLimit) || after.TotalAlloc-before.TotalAlloc > 16<<10 {
		t.Fatalf("sequence copied before reservation: allocated=%d err=%v", after.TotalAlloc-before.TotalAlloc, err)
	}
	budget, err = EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	out = NewBudgetBuffer(budget)
	if err := EncodeExtensionContents(out, []byte{0x20}, spans, 0); err != nil || !bytes.Equal(out.CompleteBytes(), []byte{1, 0x20}) {
		t.Fatalf("explicit contents lost priority: %v", err)
	}
}
