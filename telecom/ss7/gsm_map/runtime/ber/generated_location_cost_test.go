// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_location_cost_test.go; SHA-256 8c8c38e8df4fd02cc520665e1925c4a6a13241691848eeaf689d0fa1054cc63e.
package ber

import (
	"errors"
	"testing"
)

func TestGeneratedLocationAddsNoAllocation(t *testing.T) {
	// X.690 (02/2021) §8.9 permits an empty SEQUENCE.
	wire := []byte{0x30, 0}
	allocations := testing.AllocsPerRun(1000, func() {
		options := TrackMAPForm(nil)
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
	options := TrackMAPForm(nil)
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

func TestGeneratedLocationTracksGenericField(t *testing.T) {
	// X.690 (02/2021) §8.23.10 and TS 29.002 V19.1.0 §17.1.1:
	// tracking must preserve whether a received leaf was applied after its
	// marker, including same-named parents, for both wire-text and MAP reports.
	for _, kind := range []string{"utf8", "map string"} {
		for _, test := range []struct {
			name                         string
			enclosing, trackFirst, apply bool
			want                         string
		}{
			{"mark then track", false, false, true, "field"},
			{"tracked same-named parent", true, true, false, "field.field"},
			{"tracked same-named leaf", true, true, true, "field.field"},
			{"same-named parent then track", true, false, false, "field.field"},
		} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				wire := []byte{0x30, 3, 0x0c, 1, 0xff}
				if kind == "map string" {
					wire = []byte{0x30, 5, 0xa0, 3, 4, 1, 'A'}
				}
				var reports ViolationLog
				options := []DecodeOption{WithTolerance(&reports)}
				if test.enclosing {
					options = ChildDecodeOptions(options, "field")
				}
				options = LocateDecodedElement(wire, "Module.Root", options)
				track := TrackBERForm
				if kind == "map string" {
					track = TrackMAPForm
				}
				if test.trackFirst {
					options = track(options)
				}
				MarkPreflightTarget(options, "field", wire[2:])
				if test.apply {
					options = ChildDecodeOptions(options, "field")
				}
				if !test.trackFirst {
					options = track(options)
				}
				if kind == "utf8" {
					if _, _, err := DecodeString(wire[2:], 12, options...); err != nil {
						t.Fatal(err)
					}
				} else {
					config, err := decodeOptions(options)
					if err != nil {
						t.Fatal(err)
					}
					beginMAPDecode(config.form, config.location, options, wire)
					if err := checkMAPStringForm(true, 4, options); err != nil {
						t.Fatal(err)
					}
					if err := LocateDecodeError(nil, options); err != nil {
						t.Fatal(err)
					}
				}
				violations := reports.Snapshot()
				if len(violations) != 1 || violations[0].Path != test.want || violations[0].Offset == nil || *violations[0].Offset != 2 || len(violations[0].ChildIndexes) != 1 || violations[0].ChildIndexes[0] != 0 || violations[0].Source != "Module.Root.field" {
					t.Fatalf("tracked field location: %+v, want %s at2 child[0]", violations, test.want)
				}
			})
		}
	}
}
