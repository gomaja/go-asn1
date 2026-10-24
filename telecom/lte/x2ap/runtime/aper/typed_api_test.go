// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/typed_api_test.go; SHA-256 ca1882d14a949bd0fc9e0c4dc2145c2f50e2df4ad497bfa66a9b87a4a392a2b6.
package aper

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestTypedViewsOwnTheirContents(t *testing.T) {
	original := []byte{3}
	spans := []BitSpan{{Start: 0, End: 8}}
	padding := []PaddingSpan{{Span: BitSpan{Start: 7, End: 8}, Width: 1}}
	form := NewReceivedForm(true, original, Location{Path: "value", Spans: spans, HasWireLocation: true}, padding)
	original[0] = 0
	spans[0].End = 0
	padding[0].Width = 0
	if !form.Present() || !bytes.Equal(form.OriginalBytes(), []byte{3}) || form.Location().Spans[0].End != 8 || form.Padding()[0].Width != 1 {
		t.Fatal("received form borrowed caller memory")
	}
	b, l, p := form.OriginalBytes(), form.Location(), form.Padding()
	b[0] = 0
	l.Spans[0].End = 0
	p[0].Width = 0
	if form.OriginalBytes()[0] != 3 || form.Location().Spans[0].End != 8 || form.Padding()[0].Width != 1 {
		t.Fatal("received-form accessor returned mutable storage")
	}
	complete := NewCompleteReceivedForm(true, []byte{0}, "root", true, CompletePadding{})
	if !complete.Present() || !complete.Location().HasWireLocation || complete.Location().Spans[0].End != 8 {
		t.Fatal("complete framing lost its location")
	}
	opaque := NewOpaqueOpenType([]byte{1}).WithPath("future").Detached()
	if opaque.Origin().Reason != CallerSupplied || opaque.Origin().Location.Path != "future" || opaque.Bytes()[0] != 1 {
		t.Fatal("caller opaque provenance changed")
	}
	opaque.Bytes()[0] = 2
	if opaque.Bytes()[0] != 1 {
		t.Fatal("opaque byte accessor borrowed storage")
	}
	known, err := NewOpaqueOpenTypeWithState([]byte{0}, ApplyDecodeOptions())
	if err != nil || known.ChildDecodeBuffer() == nil {
		t.Fatalf("nested decoder options: %v", err)
	}
	if EncodeWithoutReplay() || !EncodeWithoutReplay(WithoutReplay()) {
		t.Fatal("fresh option was not applied")
	}
}

func TestTypedChoiceExtensions(t *testing.T) {
	payload := []byte{1}
	extension, err := NewChoiceExtension(3, payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 2
	if extension.Index() != 3 || extension.Contents()[0] != 1 || extension.Origin().Reason != CallerSupplied {
		t.Fatal("choice extension lost ownership or selector")
	}
	extension.Contents()[0] = 3
	if extension.Contents()[0] != 1 {
		t.Fatal("choice extension accessor borrowed content")
	}
	if _, err := NewChoiceExtension(math.MaxUint64, nil); !errors.Is(err, ErrLimit) {
		t.Fatal("overflowing choice index accepted")
	}
	bb := NewBitBuffer()
	if err := EncodeOpenTypeAligned(bb, []byte{1}); err != nil {
		t.Fatal(err)
	}
	received, err := DecodeChoiceExtensionAligned(NewBitBufferFromBytes(bb.CompleteBytes()), 3)
	if err != nil || received.Index() != 3 || !bytes.Equal(received.Contents(), []byte{1}) || !received.Origin().HasWireLocation {
		t.Fatalf("received choice = %+v, %v", received, err)
	}
	if _, err := DecodeChoiceExtensionAligned(NewBitBufferFromBytes(nil), -1); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("negative choice index accepted")
	}
	origin := received.Origin()
	origin.Location.Spans[0].End = 0
	if received.Origin().Location.Spans[0].End == 0 {
		t.Fatal("choice origin borrowed spans")
	}
}

func TestTypedSequenceExtensions(t *testing.T) {
	var count int64
	var present []bool
	var data [][]byte
	var origins []OpaqueOrigin
	if err := SetSequenceExtension(&count, &present, &data, &origins, 2, []byte{9}); err != nil {
		t.Fatal(err)
	}
	views := SequenceExtensionViews(present, data, origins)
	if len(views) != 1 || views[0].Index() != 2 || views[0].Contents()[0] != 9 || views[0].Origin().Reason != CallerSupplied {
		t.Fatal("sequence extension view lost value")
	}
	views[0].Contents()[0] = 0
	if data[2][0] != 9 {
		t.Fatal("extension view borrowed bytes")
	}
	for _, index := range []uint64{16383, math.MaxUint64} {
		if err := SetSequenceExtension(&count, &present, &data, &origins, index, nil); !errors.Is(err, ErrLimit) {
			t.Fatal("invalid extension index accepted")
		}
	}
	if count != 2 || len(present) != 3 || data[2][0] != 9 {
		t.Fatal("refused extension edit changed state")
	}
	if err := RemoveSequenceExtension(&count, &present, &data, &origins, 2); err != nil {
		t.Fatal(err)
	}
	if count != 0 || present != nil || data != nil || origins != nil {
		t.Fatal("last extension removal retained state")
	}
	if err := RemoveSequenceExtension(&count, &present, &data, &origins, 2); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("absent extension removal accepted")
	}
	counts := map[string]int{"one": math.MaxInt}
	if IncrementCount(counts, "one") != math.MaxInt || IncrementCount(counts, "two") != 1 {
		t.Fatal("element count failed to saturate")
	}
}

func TestSequenceExtensionOriginSnapshot(t *testing.T) {
	origin := OpaqueOrigin{Location: Location{Path: "addition", Spans: []BitSpan{{Start: 0, End: 8}}, HasWireLocation: true}}
	extension := NewSequenceExtension(2, []byte{0}, origin)
	origin.Location.Spans[0].End = 0
	if extension.Origin().Location.Spans[0].End != 8 {
		t.Fatal("sequence extension borrowed origin spans")
	}
}

func TestFieldReceivedFormAlignmentAndOwnership(t *testing.T) {
	reader := NewBitBufferFromBytes([]byte{171, 205})
	if _, err := reader.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	start := reader.BitPos()
	if _, err := reader.ReadBits(10); err != nil {
		t.Fatal(err)
	}
	form, err := CaptureFieldReceivedForm(reader, start, "field")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(form.OriginalBytes(), []byte{94, 64}) || form.Location().Spans[0] != (BitSpan{Start: 3, End: 13}) {
		t.Fatalf("received bit range = %+v", form.Location())
	}
	writer := NewBitBuffer()
	if err := writer.WriteBits(5, 3); err != nil {
		t.Fatal(err)
	}
	replayed, err := ReplayFieldReceivedForm(writer, form)
	if err != nil || !replayed || writer.BitPos() != 13 || !bytes.Equal(writer.CompleteBytes(), []byte{171, 200}) {
		t.Fatalf("field replay = %x, %v", writer.CompleteBytes(), err)
	}
	misaligned := NewBitBuffer()
	if replayed, err := ReplayFieldReceivedForm(misaligned, form); err != nil || replayed || misaligned.BitPos() != 0 {
		t.Fatal("field replay ignored changed alignment")
	}
	for _, bad := range []int{-1, 14} {
		if _, err := CaptureFieldReceivedForm(reader, bad, "field"); !errors.Is(err, ErrInvalidValue) {
			t.Fatal("invalid field cursor accepted")
		}
	}
	if _, err := CaptureFieldReceivedForm(nil, 0, "field"); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("nil field reader accepted")
	}
}

func TestFieldReceivedFormAcrossFragments(t *testing.T) {
	payload := bytes.Repeat([]byte{5}, 16385)
	wire := append([]byte{193}, payload[:16384]...)
	wire = append(wire, 1, payload[16384])
	raw, err := DecodeOpaqueOpenTypeAligned(NewBitBufferFromBytes(wire), UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	if _, err := child.ReadBytes(len(payload)); err != nil {
		t.Fatal(err)
	}
	form, err := CaptureFieldReceivedForm(child, 0, "field")
	if err != nil || !bytes.Equal(form.OriginalBytes(), payload) {
		t.Fatal("fragmented field contents lost")
	}
	location := form.Location()
	if !location.HasWireLocation || len(location.Spans) != 2 || location.Spans[0].End+8 != location.Spans[1].Start {
		t.Fatalf("fragment map = %+v", location)
	}
}
