// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/linear_encoder_test.go; SHA-256 ac8947f9e6cff2944df80b4022e93ef95865d3b2864fdef04d2348b5d65ef53e.
package ber

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestLinearEncoderMatchesNestedTLV(t *testing.T) {
	innerTag := tag.Tag{Class: tag.ClassContextSpecific, Number: 201, Constructed: true}
	outerTag := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}
	payload := bytes.Repeat([]byte{0x7f}, 200)
	child, err := EncodeTLV(innerTag, payload)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeTLV(outerTag, append(EncodeBoolean(true), child...))
	if err != nil {
		t.Fatal(err)
	}
	var encoder LinearEncoder
	outer := encoder.Begin(outerTag)
	encoder.Append(EncodeBoolean(true))
	inner := encoder.Begin(innerTag)
	encoder.Append(payload)
	if err := encoder.End(inner); err != nil {
		t.Fatal(err)
	}
	if err := encoder.End(outer); err != nil {
		t.Fatal(err)
	}
	got, err := encoder.bytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("linear encoding = %x, %v; want %x", got, err, want)
	}
	again, err := encoder.bytes()
	if err != nil || !bytes.Equal(again, want) {
		t.Fatalf("second linear encoding = %x, %v; want %x", again, err, want)
	}
}

func TestLinearEncoderPoolKeepsReturnedBytes(t *testing.T) {
	first := acquireLinearEncoder()
	frame := first.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	first.Append([]byte{0x05, 0x00})
	if err := first.End(frame); err != nil {
		t.Fatal(err)
	}
	wire, err := first.bytes()
	if err != nil {
		t.Fatal(err)
	}
	releaseLinearEncoder(first)
	second := acquireLinearEncoder()
	second.Append([]byte{0xff, 0xff, 0xff, 0xff})
	releaseLinearEncoder(second)
	if !bytes.Equal(wire, []byte{0x30, 0x02, 0x05, 0x00}) {
		t.Fatalf("returned bytes changed after reuse: %x", wire)
	}
}

func TestReleaseOversizedLinearEncoderClearsState(t *testing.T) {
	encoder := acquireLinearEncoder()
	encoder.Append(bytes.Repeat([]byte{0xaa}, 70<<10))
	encoder.sortElements = append(encoder.sortElements, linearSortElement{wire: []byte{1}})
	encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 7}, false)
	releaseLinearEncoder(encoder)
	if cap(encoder.raw) > len(encoder.inlineRaw) || len(encoder.raw) != 0 ||
		len(encoder.sortElements) != 0 || encoder.inlineSortItems[0].wire != nil ||
		encoder.hasNextTag || encoder.nextTag != (tag.Tag{}) {
		t.Fatal("released oversized builder retains state")
	}
}

func TestEncodeLinearAbortsOnError(t *testing.T) {
	if _, err := EncodeLinear(nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil append function: %v", err)
	}
	want := errors.New("append failed")
	got, err := EncodeLinear(func(encoder *LinearEncoder) error {
		encoder.Append([]byte{1, 1, 0xff})
		return want
	})
	if !errors.Is(err, want) || got != nil {
		t.Fatalf("failed encode returned %x, %v", got, err)
	}
	got, err = EncodeLinear(func(encoder *LinearEncoder) error {
		encoder.Append([]byte{5, 0})
		return nil
	})
	if err != nil || !bytes.Equal(got, []byte{5, 0}) {
		t.Fatalf("next encode returned %x, %v", got, err)
	}
}

func TestLinearEncoderOrdersSiblingLengths(t *testing.T) {
	var encoder LinearEncoder
	outer := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	var wantChildren []byte
	for index, payload := range [][]byte{bytes.Repeat([]byte{1}, 200), {2}, bytes.Repeat([]byte{3}, 128)} {
		tagged := tag.Tag{Class: tag.ClassContextSpecific, Number: index}
		child := encoder.Begin(tagged)
		encoder.Append(payload)
		if err := encoder.End(child); err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: index, Constructed: true}, payload)
		if err != nil {
			t.Fatal(err)
		}
		wantChildren = append(wantChildren, encoded...)
	}
	if err := encoder.End(outer); err != nil {
		t.Fatal(err)
	}
	want, err := EncodeSequence(wantChildren)
	if err != nil {
		t.Fatal(err)
	}
	got, err := encoder.bytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("linear encoding = %x, %v; want %x", got, err, want)
	}
}

func TestLinearEncoderBooleanForms(t *testing.T) {
	for _, tc := range []struct {
		value bool
		raw   byte
		want  []byte
	}{
		{false, 0, []byte{1, 1, 0}},
		{true, 0, []byte{1, 1, 0xff}},
		{true, 0x7f, []byte{1, 1, 0x7f}},
	} {
		var encoder LinearEncoder
		encoder.AppendBoolean(tc.value, tc.raw)
		got, err := encoder.bytes()
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("AppendBoolean(%v, %x) = %x, %v; want %x", tc.value, tc.raw, got, err, tc.want)
		}
	}
}

func TestLinearEncoderRejectsUnstartedFrame(t *testing.T) {
	var encoder LinearEncoder
	encoder.Append([]byte{0x01, 0x01, 0x00})
	if err := encoder.End(LinearFrame{}); err == nil {
		t.Fatal("zero frame was accepted")
	}
}

func TestLinearEncoderImplicitTagAndLengthForm(t *testing.T) {
	for _, tc := range []struct {
		indefinite bool
		want       []byte
	}{
		{false, []byte{0xbf, 0x20, 0x81, 0x03, 0x01, 0x01, 0xff}},
		{true, []byte{0xbf, 0x20, 0x80, 0x01, 0x01, 0xff, 0, 0}},
	} {
		var encoder LinearEncoder
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 32}, tc.indefinite)
		encoder.Append([]byte{0x30, 0x81, 0x03, 0x01, 0x01, 0xff})
		got, err := encoder.bytes()
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("implicit replay = %x, %v; want %x", got, err, tc.want)
		}
	}
}

func TestLinearEncoderNestedImplicitTags(t *testing.T) {
	// ITU-T X.690 (02/2021) §8.14.4: the outer assignment replaces
	// the identifier produced by the inner tagged assignment.
	outer := tag.Tag{Class: tag.ClassContextSpecific, Number: 7}
	inner := tag.Tag{Class: tag.ClassContextSpecific, Number: 5}
	for _, built := range []bool{false, true} {
		var encoder LinearEncoder
		encoder.OverrideNextTag(outer, false)
		encoder.OverrideNextTag(inner, false)
		if built {
			frame := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
			encoder.Append([]byte{1, 1, 0})
			if err := encoder.End(frame); err != nil {
				t.Fatal(err)
			}
		} else {
			encoder.Append([]byte{0x30, 3, 1, 1, 0})
		}
		got, err := encoder.bytes()
		want := []byte{0xa7, 3, 1, 1, 0}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("built=%t: got %x, %v; want %x", built, got, err, want)
		}
	}
}

func TestLinearEncoderDEROrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setOf bool
		left  []byte
		right []byte
		want  func([]byte) ([]byte, error)
	}{
		{"SET", false, []byte{0x85, 0x01, 0x01}, []byte{0x81, 0x01, 0x01}, EncodeDERSet},
		{"SET OF", true, []byte{0x01, 0x01, 0xff}, []byte{0x01, 0x01, 0x00}, EncodeDERSetOf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var encoder LinearEncoder
			setTag := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSet}
			var frame LinearFrame
			if tc.setOf {
				frame = encoder.BeginDERSetOf(setTag)
			} else {
				frame = encoder.BeginDERSet(setTag)
			}
			encoder.Append(tc.left)
			encoder.Append(tc.right)
			if err := encoder.End(frame); err != nil {
				t.Fatal(err)
			}
			got, err := encoder.bytes()
			if err != nil {
				t.Fatal(err)
			}
			want, err := tc.want(append(append([]byte(nil), tc.left...), tc.right...))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("DER order = %x, %v; want %x", got, err, want)
			}
		})
	}
}

func TestLinearEncoderResultCapacityBound(t *testing.T) {
	for _, size := range []int{0, 2, 8, 127, 128, 2048} {
		payload := bytes.Repeat([]byte{0x7f}, size)
		encoded, err := EncodeLinear(func(e *LinearEncoder) error { e.Append(payload); return nil })
		if err != nil || !bytes.Equal(encoded, payload) {
			t.Fatalf("size %d: %x, %v", size, encoded, err)
		}
		// MAP retains a bounded transport-wrapper reserve, independent of payload size.
		if cap(encoded)-len(encoded) > 64 {
			t.Fatalf("size %d: retained %d unused bytes", size, cap(encoded)-len(encoded))
		}
	}
}
