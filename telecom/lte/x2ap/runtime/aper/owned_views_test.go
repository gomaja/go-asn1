// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owned_views_test.go; SHA-256 8cc8ea83fdb8fb026db8d8ea0569fbac25af1739bb865060cd526a93b724c383.
package aper

import (
	"bytes"
	"math"
	"testing"
)

func TestOwnedReceivedViewsDoNotExposeTheirStorage(t *testing.T) {
	input := []byte{0x80}
	location := Location{Path: "Value", Spans: []BitSpan{{Start: 0, End: 8}}, HasWireLocation: true}
	padding := []PaddingSpan{{Span: BitSpan{Start: 1, End: 8}, Width: 7}}
	received := NewReceivedForm(true, input, location, padding)
	input[0] = 0
	location.Spans[0].End = 99
	padding[0].Width = 0
	if !received.Present() || !bytes.Equal(received.OriginalBytes(), []byte{0x80}) || received.Location().Spans[0].End != 8 || received.Padding()[0].Width != 7 {
		t.Fatal("constructor retained mutable input")
	}
	received.OriginalBytes()[0] = 0
	received.Location().Spans[0].End = 99
	received.Padding()[0].Width = 0
	if received.OriginalBytes()[0] != 0x80 || received.Location().Spans[0].End != 8 || received.Padding()[0].Width != 7 {
		t.Fatal("accessors exposed mutable storage")
	}
	complete := NewCompleteReceivedForm(true, []byte{0x80}, "Value", true, CompletePadding{count: 7})
	if !complete.Present() || complete.Padding()[0].Span != (BitSpan{Start: 1, End: 8}) {
		t.Fatal("complete padding has the wrong span")
	}
}

func TestOwnedChoiceAndSequenceExtensionViews(t *testing.T) {
	choice, err := NewChoiceExtension(3, []byte{0x80})
	if err != nil {
		t.Fatal(err)
	}
	if choice.Index() != 3 || choice.Contents()[0] != 0x80 || choice.Origin().Reason != CallerSupplied {
		t.Fatal("choice identity lost")
	}
	choice.Contents()[0] = 0
	if choice.Contents()[0] != 0x80 {
		t.Fatal("choice contents alias")
	}
	var count int64
	var present []bool
	var data [][]byte
	var origins []OpaqueOrigin
	if err := SetSequenceExtension(&count, &present, &data, &origins, 3, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	views := SequenceExtensionViews(present, data, origins)
	if len(views) != 1 || views[0].Index() != 3 || views[0].Contents()[0] != 0x80 || views[0].Origin().Reason != CallerSupplied {
		t.Fatal("sequence identity lost")
	}
	views[0].Contents()[0] = 0
	if data[3][0] != 0x80 {
		t.Fatal("sequence contents alias")
	}
	if err := RemoveSequenceExtension(&count, &present, &data, &origins, 3); err != nil {
		t.Fatal(err)
	}
	if count != 0 || present != nil || data != nil || origins != nil {
		t.Fatal("removing the last addition retained bitmap state")
	}
	counts := map[int]int{1: math.MaxInt}
	if IncrementCount(counts, 1) != math.MaxInt || IncrementCount(counts, 2) != 1 {
		t.Fatal("occurrence counter overflowed")
	}
}

func TestDetachedOpaqueUsesTheEncodingOperation(t *testing.T) {
	state := ApplyDecodeOptions()
	raw, err := NewOpaqueOpenTypeWithState([]byte{0x80}, state)
	if err != nil {
		t.Fatal(err)
	}
	if raw.BudgetBuffer().Budget() != DecodeBuffer(state).Budget() {
		t.Fatal("selected value reset the decode budget")
	}
	detached := raw.Detached()
	budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxOutputBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	copied, err := detached.EncodeBytes(budget)
	if err != nil || !bytes.Equal(copied, []byte{0x80}) {
		t.Fatal(err)
	}
	copied[0] = 0
	if detached.Bytes()[0] != 0x80 {
		t.Fatal("encode exposed opaque storage")
	}
	if state.Usage().AllocatedBytes <= operationMetadataBytes {
		t.Fatal("selected input copy was not charged")
	}
	if EncodeWithoutReplay() || !EncodeWithoutReplay(WithoutReplay()) {
		t.Fatal("fresh encoding option lost")
	}
}
