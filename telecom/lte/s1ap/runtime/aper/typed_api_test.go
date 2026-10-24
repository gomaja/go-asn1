// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/typed_api_test.go; SHA-256 eec02958565de48dcb1656592b329c0d8966a15abba5f16df803a4b2c7f054e6.
package aper

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestReceivedFormAndOpaqueOwnership(t *testing.T) {
	input := []byte{0x81}
	location := Location{Path: "Value", Spans: []BitSpan{{Start: 8, End: 16}}, HasWireLocation: true}
	padding := []PaddingSpan{{Span: BitSpan{Start: 15, End: 16}, Value: 1, Width: 1}}
	form := NewReceivedForm(true, input, location, padding)
	input[0] = 0
	location.Spans[0].Start = 0
	padding[0].Value = 0
	if !form.Present() || !bytes.Equal(form.OriginalBytes(), []byte{0x81}) || form.Location().Spans[0].Start != 8 || form.Padding()[0].Value != 1 {
		t.Fatal("received form aliases constructor input")
	}
	returned := form.OriginalBytes()
	returned[0] = 0
	loc := form.Location()
	loc.Spans[0].Start = 0
	pads := form.Padding()
	pads[0].Value = 0
	if form.OriginalBytes()[0] != 0x81 || form.Location().Spans[0].Start != 8 || form.Padding()[0].Value != 1 {
		t.Fatal("received form accessors alias state")
	}
	complete := NewCompleteReceivedForm(true, []byte{0x81}, "Top", true, CompletePadding{bits: 1, count: 1})
	if complete.Location().Spans[0].End != 8 || complete.Padding()[0].Span.Start != 7 {
		t.Fatal("complete received locations")
	}
	if NewCompleteReceivedForm(false, nil, "Fresh", false, CompletePadding{}).Location().HasWireLocation {
		t.Fatal("fresh form invented a wire location")
	}
	raw := NewOpaqueOpenType([]byte{0x80})
	contents := raw.Bytes()
	contents[0] = 0
	if raw.Bytes()[0] != 0x80 || raw.Origin().Reason != CallerSupplied {
		t.Fatal("opaque constructor lost ownership or origin")
	}
	bb := NewBitBufferFromBytes([]byte{1, 0x80})
	received, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{Document: "test", Edition: "test"})
	if err != nil {
		t.Fatal(err)
	}
	received = received.WithPath("Outer.Value")
	detached := received.Detached()
	if detached.parent != nil || detached.Origin().Location.Path != "Outer.Value" || !bytes.Equal(detached.Bytes(), []byte{0x80}) {
		t.Fatal("detachment lost contents or origin")
	}
	origin := detached.Origin()
	origin.Location.Spans[0].Start = 99
	if detached.Origin().Location.Spans[0].Start == 99 {
		t.Fatal("opaque origin accessor aliases spans")
	}
	state := ApplyDecodeOptions(WithLimits(Limits{MaxWork: 1025}))
	configured, err := NewOpaqueOpenTypeWithState([]byte{0x80}, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configured.ChildDecodeBuffer().ReadBits(2); !errors.Is(err, ErrLimit) {
		t.Fatalf("nested options ignored: %v", err)
	}
	if _, err := NewOpaqueOpenTypeWithState([]byte{0}, ApplyDecodeOptions(WithLimits(Limits{MaxWork: ^uint64(0)}))); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid option accepted: %v", err)
	}
	if EncodeWithoutReplay() || !EncodeWithoutReplay(EncodeOption{}, WithoutReplay()) {
		t.Fatal("fresh encoding option lost")
	}
}

func TestChoiceExtensionOwnershipAndBounds(t *testing.T) {
	input := []byte{0x80}
	value, err := NewChoiceExtension(3, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 0
	if value.Index() != 3 || !bytes.Equal(value.Contents(), []byte{0x80}) || value.Origin().Reason != CallerSupplied {
		t.Fatal("choice constructor ownership")
	}
	data := value.Contents()
	data[0] = 0
	if value.Contents()[0] != 0x80 {
		t.Fatal("choice view mutable")
	}
	if _, err := NewChoiceExtension(math.MaxUint64, nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("invalid index: %v", err)
	}
	received, err := DecodeChoiceExtensionAligned(NewBitBufferFromBytes([]byte{1, 0x80}), 3)
	if err != nil {
		t.Fatal(err)
	}
	if received.Index() != 3 || received.Origin().Reason != UnknownSelector || received.Origin().SourceVersion != "V19.2.0" || received.Origin().Location.Path != "UnknownExtension" {
		t.Fatal("choice received provenance")
	}
	origin := received.Origin()
	origin.Location.Spans[0].Start = 99
	if received.Origin().Location.Spans[0].Start == 99 {
		t.Fatal("choice origin mutable")
	}
	if _, err := DecodeChoiceExtensionAligned(NewBitBufferFromBytes([]byte{1, 0}), -1); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("negative received index accepted")
	}
	if _, err := DecodeChoiceExtensionAligned(NewBitBufferFromBytes([]byte{1}), 0); err == nil {
		t.Fatal("truncated choice content accepted")
	}
}

func TestSequenceExtensionOwnershipEditsAndCountSaturation(t *testing.T) {
	counts := map[string]int{"full": math.MaxInt}
	if IncrementCount(counts, "new") != 1 || IncrementCount(counts, "full") != math.MaxInt {
		t.Fatal("count overflow")
	}
	origin := OpaqueOrigin{Reason: UnknownSelector, Location: Location{Path: "Extensions", Spans: []BitSpan{{Start: 8, End: 16}}}}
	input := []byte{0x80}
	extension := NewSequenceExtension(1, input, origin)
	input[0] = 0
	origin.Location.Spans[0].Start = 0
	if extension.Index() != 1 || extension.Contents()[0] != 0x80 || extension.Origin().Location.Spans[0].Start != 8 {
		t.Fatal("sequence constructor aliases input")
	}
	spans := extension.Origin()
	spans.Location.Spans[0].Start = 99
	if extension.Origin().Location.Spans[0].Start == 99 {
		t.Fatal("sequence origin mutable")
	}
	var count int64
	var present []bool
	var data [][]byte
	var origins []OpaqueOrigin
	if err := SetSequenceExtension(&count, &present, &data, &origins, 3, []byte{0x81}); err != nil {
		t.Fatal(err)
	}
	if count != 3 || !present[3] || data[3][0] != 0x81 || origins[3].Reason != CallerSupplied {
		t.Fatal("set addition failed")
	}
	origins[3] = extension.Origin()
	views := SequenceExtensionViews(present, data, origins)
	if len(views) != 1 || views[0].Index() != 3 || views[0].Origin().Location.Path != "Extensions[3]" {
		t.Fatal("addition views lost source location")
	}
	returned := views[0].Contents()
	returned[0] = 0
	if data[3][0] != 0x81 {
		t.Fatal("addition contents mutable")
	}
	if err := SetSequenceExtension(&count, &present, &data, &origins, 1, []byte{}); err != nil {
		t.Fatal(err)
	}
	if data[1] == nil {
		t.Fatal("present empty is absent")
	}
	if err := RemoveSequenceExtension(&count, &present, &data, &origins, 3); err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(data) != 2 {
		t.Fatal("remove failed to shrink tail")
	}
	if err := RemoveSequenceExtension(&count, &present, &data, &origins, 1); err != nil {
		t.Fatal(err)
	}
	if count != 0 || data != nil || present != nil || origins != nil {
		t.Fatal("last removal retained state")
	}
	for _, index := range []uint64{16383, math.MaxUint64} {
		if err := SetSequenceExtension(&count, &present, &data, &origins, index, nil); !errors.Is(err, ErrLimit) {
			t.Fatal("invalid addition index accepted")
		}
		if err := RemoveSequenceExtension(&count, &present, &data, &origins, index); !errors.Is(err, ErrInvalidValue) {
			t.Fatal("invalid removal accepted")
		}
	}
	if err := SetSequenceExtension(nil, &present, &data, &origins, 0, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("nil state accepted")
	}
	present = []bool{true}
	data = nil
	if err := RemoveSequenceExtension(&count, &present, &data, &origins, 0); !errors.Is(err, ErrInvalidValue) || !present[0] {
		t.Fatal("inconsistent state changed on refusal")
	}
}
