// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/linear_encoder_test.go; SHA-256 a9985a22952bedba258348f5ab377987b934ab94e09b83ec7d5886db5706e87d.
package ber

import (
	"bytes"
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

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

func TestLinearEncoderResultHasNoUnusedCapacity(t *testing.T) {
	for _, size := range []int{0, 2, 8, 127, 128, 2048} {
		payload := bytes.Repeat([]byte{0x7f}, size)
		encoded, err := EncodeLinear(func(e *LinearEncoder) error { e.Append(payload); return nil })
		if err != nil || !bytes.Equal(encoded, payload) {
			t.Fatalf("size %d: %x, %v", size, encoded, err)
		}
		if cap(encoded) != len(encoded) {
			t.Fatalf("size %d: retained %d unused bytes", size, cap(encoded)-len(encoded))
		}
	}
}
