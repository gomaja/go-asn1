// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owned_fragments_test.go; SHA-256 4a2d1ec2421ddf5d002aa4697d6778a8af769e1ae21e10393128ba92f723b9ae.
package aper

import (
	"bytes"
	"testing"
)

func TestOwnedFragmentedOpenTypeUsesOriginalSpans(t *testing.T) {
	// X.691 (02/2021) §11.9.3.8: one maximal 64K fragment and a tail.
	payload := make([]byte, 65540)
	for i := range payload {
		payload[i] = byte(i*13 + 7)
	}
	w := NewBitBuffer()
	if err := EncodeOpenTypeAligned(w, payload); err != nil {
		t.Fatal(err)
	}
	original, options := ownTestDecodeInput(w.Bytes(), decodeSettings{Limits: decodeLimits{MaxWork: 64 << 20}})
	b := NewBitBufferFromBytes(original)
	if err := b.setDecodeSettingsAligned(options); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(b, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	borrowed := false
	for i := range original {
		if len(child.data) > 0 && &child.data[0] == &original[i] {
			borrowed = true
			break
		}
	}
	if !borrowed {
		t.Fatal("fragmented child retained joined temporary storage")
	}
	got, err := child.ReadBytes(len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fragmented bytes differ")
	}
	if !bytes.Equal(raw.Bytes(), payload) {
		t.Fatal("opaque contents differ")
	}
}

func TestFragmentedWireSpanReplayAndAlignment(t *testing.T) {
	payload := make([]byte, 65540)
	for i := range payload {
		payload[i] = byte(i)
	}
	w := NewBitBuffer()
	if err := EncodeOpenTypeAligned(w, payload); err != nil {
		t.Fatal(err)
	}
	input, options := ownTestDecodeInput(w.Bytes(), decodeSettings{Limits: decodeLimits{MaxWork: 64 << 20}})
	parent := newTestCompleteDecodeBuffer(input, options)
	if err := parent.setDecodeSettingsAligned(options); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	if _, err := child.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	start := child.BitPos()
	if _, err := child.ReadBitsToBytes(len(payload)*8 - 7); err != nil {
		t.Fatal(err)
	}
	span := child.CaptureWireSpan(start)
	if len(span.segments) < 2 {
		t.Fatal("lost fragment source spans")
	}
	out := NewBitBuffer()
	if err := out.WriteBits(0, 3); err != nil {
		t.Fatal(err)
	}
	ok, err := span.ReplayTo(out)
	if !ok || err != nil {
		t.Fatalf("qualified replay %v %v", ok, err)
	}
	want := NewBitBuffer()
	if err := want.WriteBits(0, 3); err != nil {
		t.Fatal(err)
	}
	for bit := 3; bit < len(payload)*8-4; bit++ {
		if err := want.WriteBit(payload[bit/8] >> (7 - bit%8) & 1); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Fatal("fragmented span replay differs")
	}
	wrong := NewBitBuffer()
	if ok, err := span.ReplayTo(wrong); ok || err != nil || wrong.BitPos() != 0 {
		t.Fatal("wrong-context replay wrote bits")
	}
}
