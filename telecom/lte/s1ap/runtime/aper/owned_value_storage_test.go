// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owned_value_storage_test.go; SHA-256 ad0c6a34b36118f7231574237460bd1a843c2a5c56a7a562bda41a4988e168b9.
package aper

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestOpaqueChildReadersStorageStates(t *testing.T) {
	for _, owned := range []bool{false, true} {
		for _, size := range []int{1, 65540} {
			t.Run(fmt.Sprintf("owned=%t/size=%d", owned, size), func(t *testing.T) {
				payload := bytes.Repeat([]byte{0xab}, size)
				writer := NewBitBuffer()
				if err := EncodeOpenTypeAligned(writer, payload); err != nil {
					t.Fatal(err)
				}
				wire := writer.CompleteBytes()
				if size == 1 && !bytes.Equal(wire, []byte{1, 0xab}) {
					t.Fatalf("wire=%x", wire)
				}
				parent := NewBitBufferFromBytes(wire)
				if owned {
					var options decodeSettings
					wire, options = ownTestDecodeInput(wire, options)
					parent = newTestCompleteDecodeBuffer(wire, options)
					if err := parent.setDecodeSettingsAligned(options); err != nil {
						t.Fatal(err)
					}
				}
				raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
				if err != nil {
					t.Fatal(err)
				}
				detached := raw.Detached()
				if !reflect.DeepEqual(detached.ContentLocation(), raw.ContentLocation()) {
					t.Errorf("detaching lost content location: %+v, want %+v", detached.ContentLocation(), raw.ContentLocation())
				}
				if !reflect.DeepEqual(detached.Origin(), raw.Origin()) {
					t.Fatal("detaching lost provenance")
				}
				checkOpaqueStorage(t, raw, payload)
				checkOpaqueStorage(t, detached, payload)
				if detached.ChildDecodeBuffer().decodeBudget() == parent.decodeBudget() {
					t.Fatal("detached reader retained parent's budget")
				}
			})
		}
	}
	for _, options := range []bool{false, true} {
		t.Run(fmt.Sprintf("caller/options=%t", options), func(t *testing.T) {
			input := []byte{0xab}
			value := NewOpaqueOpenType(input)
			if options {
				var err error
				value, err = newOpaqueOpenTypeWithSettings(input, decodeSettings{})
				if err != nil {
					t.Fatal(err)
				}
			}
			input[0] = 0
			checkOpaqueStorage(t, value, []byte{0xab})
			checkOpaqueStorage(t, value.Detached(), []byte{0xab})
		})
	}
}

func checkOpaqueStorage(t *testing.T, value OpaqueOpenType, payload []byte) {
	t.Helper()
	first, second := value.ChildDecodeBuffer(), value.ChildDecodeBuffer()
	got, err := first.ReadBytes(len(payload))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("child contents=%x error=%v; want %d payload octets", got, err, len(payload))
	}
	if second.BitPos() != 0 {
		t.Fatal("readers share a cursor")
	}
	got, err = second.ReadBytes(len(payload))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("second reader: %v", err)
	}
	view := value.Bytes()
	if !bytes.Equal(view, payload) {
		t.Fatal("Bytes differs from child reader")
	}
	view[0] ^= 0xff
	if !bytes.Equal(value.Bytes(), payload) {
		t.Fatal("Bytes exposes writable storage")
	}
	var span WireSpan
	value.RetainContents(&span)
	if !bytes.Equal(span.Bytes(), payload) {
		t.Fatal("retained contents differ")
	}
}

func TestChoiceIndependentChildReaders(t *testing.T) {
	for _, owned := range []bool{false, true} {
		for _, size := range []int{1, 65540} {
			t.Run(fmt.Sprintf("owned=%t/size=%d", owned, size), func(t *testing.T) {
				payload := bytes.Repeat([]byte{0xab}, size)
				writer := NewBitBuffer()
				if err := EncodeOpenTypeAligned(writer, payload); err != nil {
					t.Fatal(err)
				}
				wire := writer.CompleteBytes()
				parent := NewBitBufferFromBytes(wire)
				if owned {
					var options decodeSettings
					wire, options = ownTestDecodeInput(wire, options)
					parent = newTestCompleteDecodeBuffer(wire, options)
					if err := parent.setDecodeSettingsAligned(options); err != nil {
						t.Fatal(err)
					}
				}
				value, err := DecodeChoiceExtensionAligned(parent, 3)
				if err != nil {
					t.Fatal(err)
				}
				for _, enclosing := range []*BitBuffer{parent, nil} {
					reader := value.ChildDecodeBuffer(enclosing)
					got, err := reader.ReadBytes(len(payload))
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("choice contents: %v", err)
					}
					if enclosing == nil && reader.decodeBudget() == parent.decodeBudget() {
						t.Fatal("independent choice reader retained parent budget")
					}
				}
				got := value.Contents()
				got[0] ^= 0xff
				if value.Index() != 3 || !bytes.Equal(value.Contents(), payload) {
					t.Fatal("choice accessor exposes storage")
				}
			})
		}
	}
	t.Run("caller", func(t *testing.T) {
		input := []byte{0xab}
		value, err := NewChoiceExtension(3, input)
		if err != nil {
			t.Fatal(err)
		}
		input[0] = 0
		got, err := value.ChildDecodeBuffer(nil).ReadBits(8)
		if err != nil || got != 0xab {
			t.Fatalf("caller choice reader=%x, %v", got, err)
		}
	})
}

func TestDetachedOpaquePreservesNestedLocations(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprintf("owned=%t", owned), func(t *testing.T) {
			wire := []byte{2, 1, 0xab}
			parent := NewBitBufferFromBytes(wire)
			if owned {
				var options decodeSettings
				wire, options = ownTestDecodeInput(wire, options)
				parent = newTestCompleteDecodeBuffer(wire, options)
				if err := parent.setDecodeSettingsAligned(options); err != nil {
					t.Fatal(err)
				}
			}
			outer, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecodeOpaqueOpenTypeAligned(outer.Detached().ChildDecodeBuffer(), UnknownSelector, SourceRule{})
			if err != nil {
				t.Fatal(err)
			}
			want := Location{Spans: []BitSpan{{Start: 16, End: 24}}, HasWireLocation: true}
			if got := inner.ContentLocation(); !reflect.DeepEqual(got, want) {
				t.Fatalf("content location=%+v, want %+v", got, want)
			}
			if !bytes.Equal(inner.Bytes(), []byte{0xab}) {
				t.Fatal("nested detached content differs")
			}
		})
	}
}

func TestExtensionAndReceivedViewsStorageStates(t *testing.T) {
	payload := []byte{0xab, 0xcd}
	for _, image := range []bool{false, true} {
		t.Run(fmt.Sprintf("image=%t", image), func(t *testing.T) {
			data := [][]byte{append([]byte(nil), payload...)}
			spans := []WireSpan{{}}
			location := Location{Spans: []BitSpan{{Start: 0, End: 16}}, HasWireLocation: true}
			origin := OpaqueOrigin{Reason: UnknownSelector, Location: location}
			form := NewReceivedForm(true, payload, location, nil)
			if image {
				data[0] = nil
				spans[0] = OriginalWire(payload)
				form = NewReceivedSpanForm(true, spans[0], location, nil)
			}
			views := SequenceExtensionViews([]bool{true}, ExtensionContents(data, spans), []OpaqueOrigin{origin})
			if len(views) != 1 || views[0].Index() != 0 || !bytes.Equal(views[0].Contents(), payload) {
				t.Fatal("sequence extension storage differs")
			}
			contents := views[0].Contents()
			contents[0] = 0
			returnedOrigin := views[0].Origin()
			returnedOrigin.Location.Spans[0].Start = 99
			if !bytes.Equal(views[0].Contents(), payload) || views[0].Origin().Location.Spans[0].Start != 0 {
				t.Fatal("sequence extension exposes storage")
			}
			contents = form.OriginalBytes()
			contents[0] = 0
			formLocation := form.Location()
			formLocation.Spans[0].Start = 99
			if !form.Present() || !bytes.Equal(form.OriginalBytes(), payload) || form.Location().Spans[0].Start != 0 {
				t.Fatal("received form exposes storage")
			}
		})
	}
	// Caller edits override a retained span; a stale image must never hide them.
	if got := ExtensionContents([][]byte{{0x12}}, []WireSpan{OriginalWire(payload)}); !bytes.Equal(got[0], []byte{0x12}) {
		t.Fatal("received span hid caller-supplied extension content")
	}
}

func TestDetachedChildReaderOwnsWritableStorage(t *testing.T) {
	for _, owned := range []bool{false, true} {
		for _, size := range []int{1, 65540} {
			t.Run(fmt.Sprintf("owned=%t/size=%d", owned, size), func(t *testing.T) {
				payload := bytes.Repeat([]byte{0xab}, size)
				writer := NewBitBuffer()
				if err := EncodeOpenTypeAligned(writer, payload); err != nil {
					t.Fatal(err)
				}
				wire := writer.CompleteBytes()
				parent := NewBitBufferFromBytes(wire)
				if owned {
					var options decodeSettings
					wire, options = ownTestDecodeInput(wire, options)
					parent = newTestCompleteDecodeBuffer(wire, options)
					if err := parent.setDecodeSettingsAligned(options); err != nil {
						t.Fatal(err)
					}
				}
				raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
				if err != nil {
					t.Fatal(err)
				}
				raw = raw.Detached()
				reader := raw.ChildDecodeBuffer()
				if got := reader.Bytes(); len(got) != size {
					t.Fatalf("independent storage has %d octets, want %d", len(got), size)
				}
				reader.Bytes()[0] = 0
				if !bytes.Equal(raw.Bytes(), payload) {
					t.Fatal("detached reader exposes value storage")
				}
				choice := ChoiceExtension{index: 3, image: raw.image, contents: raw.bytes}
				choice.ChildDecodeBuffer(nil).Bytes()[0] = 0
				if !bytes.Equal(choice.Contents(), payload) {
					t.Fatal("independent choice reader exposes value storage")
				}
			})
		}
	}
}
