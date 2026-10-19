// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_generated_field_test.go; SHA-256 4b1e802733198b11fe91473137c8e1d43b1bfcfa7afa70048c50f2cf7c4eb89f.
package ber

import (
	"slices"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestGeneratedContextSameNamedUTF8Leaf(t *testing.T) {
	wire := structureWire(t, "3008a0068001018201ff")
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	options = TrackBERForm(options)
	owned, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(owned, "Module.Outer", options)
	MarkPreflightTarget(options, "text", owned[2:])
	child := []DecodeOption{ChildDecodeContext(options, "text")}
	child = LocateDecodedElement(owned[2:], "Module.Inner", child)
	MarkPreflightTarget(child, "text", owned[7:])
	config, err := decodeOptions(child)
	if err != nil {
		t.Fatal(err)
	}
	location := config.location
	if location == nil || location.fieldContext == nil {
		t.Fatal("generated marker was not retained")
	}
	for _, tc := range []struct {
		name    string
		options []DecodeOption
		want    bool
	}{
		{"marker only", child, false},
		{"same leaf applied", []DecodeOption{ChildDecodeContext(child, "text")}, true},
		{"different leaf", []DecodeOption{ChildDecodeContext(child, "other")}, false},
	} {
		if got := location.fieldAlreadyApplied(tc.options); got != tc.want {
			t.Errorf("%s: applied=%t want=%t", tc.name, got, tc.want)
		}
	}
	if _, err := DecodeImplicitStringValue(tag.TagUTF8String, false, owned[9:], child...); err != nil {
		t.Fatal(err)
	}
	finish(true)
	got := reports.Snapshot()
	if len(got) != 1 || got[0].Path != "text.text" || got[0].Source != "Module.Inner.text" || got[0].Offset == nil || *got[0].Offset != 7 || !slices.Equal(got[0].ChildIndexes, []int{0, 1}) {
		t.Fatalf("records=%+v", got)
	}
}
