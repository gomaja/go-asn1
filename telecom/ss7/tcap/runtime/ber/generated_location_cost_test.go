// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_location_cost_test.go; SHA-256 78b7daf3cf33a20f4991ac2044baddb93ff6b63cdae7a6d72386d9b3594a9ee9.
package ber

import (
	"errors"
	"testing"
)

func TestGeneratedLocationAddsNoAllocation(t *testing.T) {
	// X.690 (02/2021) §8.9 permits an empty SEQUENCE.
	wire := []byte{0x30, 0}
	allocations := testing.AllocsPerRun(1000, func() {
		options := TrackBERForm(nil)
		data, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(data, "Module.Empty", options)
		if err := LocateDecodeError(nil, options); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("empty generated entry allocations: %.0f", allocations)
	if allocations > 3 {
		t.Fatalf("empty generated entry allocated %.0f objects, want at most 3", allocations)
	}
}

func TestGeneratedLocationDefersAncestryStorage(t *testing.T) {
	wire := []byte{0x30, 0}
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "Module.Empty", options)
	context := options[0].(*generatedDecodeOption)
	if context.config.location.origin != nil {
		t.Fatal("successful empty decode allocated ancestry state")
	}
	err = CheckDecodedValue(options, "", "test constraint", "bad")
	var violation *ValidationError
	if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != 0 || violation.Source != "Module.Empty" {
		t.Fatalf("deferred location lost its root: %v", err)
	}
}

func TestGeneratedLocationsRetainEnclosingCall(t *testing.T) {
	wire := []byte{0x30, 3, 4, 1, 'A'}
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	root := LocateDecodedElement(data, "Module.Root", options)
	alias := LocateDecodedElement(data, "Module.Alias", root)
	child := LocateDecodedElement(data[2:], "Module.Child", ChildDecodeOptions(root, "child"))
	for _, test := range []struct {
		options []DecodeOption
		source  string
		offset  int
	}{
		{root, "Module.Root", 0},
		{alias, "Module.Alias", 0},
		{child, "Module.Child", 2},
	} {
		err := CheckDecodedValue(test.options, "", "test constraint", "bad")
		var violation *ValidationError
		if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != test.offset || violation.Source != test.source {
			t.Fatalf("enclosing call overwritten, want %s at %d: %v", test.source, test.offset, err)
		}
	}
}

func TestDialogueLocationsRetainEnclosingCall(t *testing.T) {
	// Q.773 (06/1997) §4.2.3; X.690 (02/2021) §§8.7.3, 8.18:
	// both contiguous and segmented copies retain their received location.
	apdu := locationTLV(t, 0x60, []byte{0x80, 2, 7, 0x80, 0xa1, 0x0b, 6, 9, 0x2b, 6, 1, 4, 1, 0x83, 0xb2, 3, 2}, false)
	for _, segmented := range []bool{false, true} {
		choice := locationTLV(t, 0xa0, apdu, false)
		if segmented {
			choice = locationTLV(t, 0xa1, append(locationTLV(t, 4, apdu[:1], false), locationTLV(t, 4, apdu[1:], false)...), false)
		}
		wire := locationTLV(t, 0x6b, locationTLV(t, 0x28, append([]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, choice...), false), false)
		var reports ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
		defer finish(false)
		options = TrackTCAPForm(options, "DialoguePortion")
		owned, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		owned, options, err = PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(owned, "Envelope", options)
		inner := append([]byte(nil), apdu...)
		enclosing := LocateDialogueContent(owned, inner, options)
		before, err := decodeOptions(enclosing)
		if err != nil || before.location == nil || before.location.source != "DialoguePortion" {
			t.Fatalf("missing enclosing location: %v", err)
		}
		location := before.location
		nested := LocateDecodedElement(inner, "DialoguePDU", enclosing)
		after, _ := decodeOptions(enclosing)
		child, _ := decodeOptions(nested)
		if after.location != location || after.location.source != "DialoguePortion" || child.location.source != "DialoguePDU" {
			t.Fatalf("segmented=%t: nested call replaced its enclosing location", segmented)
		}
	}
}
