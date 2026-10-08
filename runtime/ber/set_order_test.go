package ber

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func setOrderTestPosition(component tag.Tag) int {
	if component.Class != tag.ClassContextSpecific {
		return -1
	}
	switch component.Number {
	case 2:
		return 0
	case 0:
		return 1
	default:
		return -1
	}
}

func TestMarkBERSetOrder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wire     []byte
		preserve bool
	}{
		{"schema", []byte{0x31, 6, 0x82, 1, 3, 0x80, 1, 1}, false},
		{"reversed", []byte{0x31, 6, 0x80, 1, 1, 0x82, 1, 3}, true},
		{"unknown", []byte{0x31, 6, 0x82, 1, 3, 0x87, 1, 1}, true},
		{"implicit schema", []byte{0x67, 6, 0x82, 1, 3, 0x80, 1, 1}, false},
		{"implicit reversed", []byte{0x67, 6, 0x80, 1, 1, 0x82, 1, 3}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := TrackBERForm(nil)
			if err := MarkBERSetOrder(tc.wire, setOrderTestPosition, options...); err != nil {
				t.Fatal(err)
			}
			if got := BERNeedsPreservation(options); got != tc.preserve {
				t.Fatalf("preserve = %t, want %t", got, tc.preserve)
			}
		})
	}
}

func TestMarkBERSetOrderKnownUniversalSetComponent(t *testing.T) {
	// The outer tag is IMPLICIT and its single known component is a SET.
	// Scanning inside that component would inspect its fields as outer fields.
	wire := []byte{0x67, 5, 0x31, 3, 0x82, 1, 3}
	position := func(component tag.Tag) int {
		if component.Class == tag.ClassUniversal && component.Number == tag.TagSet {
			return 0
		}
		return -1
	}
	options := TrackBERForm(nil)
	if err := MarkBERSetOrder(wire, position, options...); err != nil {
		t.Fatal(err)
	}
	if BERNeedsPreservation(options) {
		t.Fatal("known nested SET was scanned as an EXPLICIT wrapper")
	}
}

func TestMarkBERSetOrderOptions(t *testing.T) {
	wire := []byte{0x31, 6, 0x82, 1, 3, 0x80, 1, 1}
	if err := MarkBERSetOrder(wire, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil schema map: %v", err)
	}
	options := TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: len(wire) - 1})})
	if err := MarkBERSetOrder(wire, setOrderTestPosition, options...); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("custom work limit: %v", err)
	}
}

func FuzzMarkBERSetOrder(f *testing.F) {
	for _, wire := range [][]byte{
		{0x31, 6, 0x82, 1, 3, 0x80, 1, 1},
		{0x31, 6, 0x80, 1, 1, 0x82, 1, 3},
		{0x31, 6, 0x82, 1, 3, 0x87, 1, 1},
		{0x31, 0x81, 6, 0x82, 1, 3, 0x80, 1, 1},
		{0x31, 0x80, 0x82, 1, 3, 0x80, 1, 1, 0, 0},
	} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		options := TrackBERForm(nil)
		if ValidateBERElement(wire, options...) != nil {
			return
		}
		outer, total, contents, err := DecodeTLV(wire)
		if err != nil || total != len(wire) || outer.Class != tag.ClassUniversal || outer.Number != tag.TagSet || !outer.Constructed {
			return
		}
		wantPreservation := BERNeedsPreservation(options)
		previous := -1
		for offset := 0; offset < len(contents); {
			component, used, _, err := DecodeTLV(contents[offset:])
			if err != nil {
				t.Fatal(err)
			}
			position := setOrderTestPosition(component)
			if position < 0 || position <= previous {
				wantPreservation = true
				break
			}
			previous = position
			offset += used
		}
		if err := MarkBERSetOrder(wire, setOrderTestPosition, options...); err != nil {
			t.Fatal(err)
		}
		if got := BERNeedsPreservation(options); got != wantPreservation {
			t.Fatalf("preserve = %t, want %t", got, wantPreservation)
		}
	})
}
