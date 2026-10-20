// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/form_options_reuse_test.go; SHA-256 f074208ce9bd7f7af19411dd77787274986e20ae7bddbf6ec883ec63a7c8c51b.
package ber

import (
	"errors"
	"strings"
	"testing"
)

// This follows the public generated-entry lifecycle, including staging and
// completion, without assigning a particular schema to the root contents.
func decodeReuseRoot(wire []byte, supplied []DecodeOption, profile bool) (err error) {
	options, commit := StageDecodeReports(supplied)
	defer func() { commit(err == nil) }()
	options = TrackMAPSyntax(options, profile)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		return err
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		return err
	}
	options = LocateDecodedElement(data, "MAP-Test.Root", options)
	return LocateDecodeError(nil, options)
}

func TestFormOptionsReuseAcrossRootDecodes(t *testing.T) {
	for _, tracker := range []struct {
		name  string
		track func([]DecodeOption) []DecodeOption
	}{
		{"BER", TrackBERForm}, {"MAP", TrackMAPForm},
	} {
		for _, tolerant := range []bool{false, true} {
			for _, mode := range []struct {
				name   string
				option DecodeOption
			}{
				{"default", nil}, {"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()},
			} {
				name := tracker.name + "/" + mode.name
				if tolerant {
					name += "/tolerant"
				} else {
					name += "/strict"
				}
				t.Run(name, func(t *testing.T) {
					var log ViolationLog
					var options []DecodeOption
					if tolerant {
						options = append(options, WithTolerance(&log))
					}
					if mode.option != nil {
						options = append(options, mode.option)
					}
					options = tracker.track(options)
					for _, input := range []string{"3003020101", "308103020102", "3003020103", "30800201040000", "3003020105"} {
						err := decodeReuseRoot(structureWire(t, input), options, true)
						var violation *ValidationError
						wantViolation := input == "308103020102"
						if wantViolation && !tolerant {
							if !errors.As(err, &violation) || !strings.Contains(violation.Constraint, "short-length") {
								t.Fatalf("root %s: error=%v, want short-length refusal", input, err)
							}
						} else if err != nil {
							t.Fatalf("root %s: %v", input, err)
						}
					}
					if tolerant {
						records := log.Snapshot()
						if len(records) != 1 || records[0].Constraint != "TS 29.002 §17.1.1: short-length" || records[0].Offset == nil || *records[0].Offset != 0 {
							t.Fatalf("reused report history=%+v", records)
						}
					}
				})
			}
		}
	}
}

func TestMAPFormOptionsReuseThenStandaloneScan(t *testing.T) {
	for _, tolerant := range []bool{false, true} {
		var options []DecodeOption
		if tolerant {
			options = []DecodeOption{WithTolerance(new(ViolationLog))}
		}
		options = TrackMAPForm(options)
		if err := decodeReuseRoot(structureWire(t, "3003020101"), options, true); err != nil {
			t.Fatal(err)
		}
		err := ValidateBERElement(structureWire(t, "318100"), options...)
		if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "generated MAP decoder") {
			t.Fatalf("standalone scan after typed decode=%v, want explicit typed-entry refusal", err)
		}
	}
}

func TestFormOptionsReuseRootSyntaxScope(t *testing.T) {
	for _, tracker := range []struct {
		name    string
		options []DecodeOption
	}{
		{"BER", TrackBERForm(nil)},
		{"MAP", TrackMAPForm(nil)},
		{"generic", TrackMAPSyntax(nil, false)},
	} {
		t.Run(tracker.name, func(t *testing.T) {
			// TS 29.002 V19.1.0 §17.1.1 applies to the root's abstract syntax,
			// regardless of a caller's tracker. Nested entries inherit that choice.
			for _, profile := range []bool{true, false, true, false} {
				var violation *ValidationError
				err := decodeReuseRoot(structureWire(t, "318100"), tracker.options, profile)
				if profile {
					if !errors.As(err, &violation) || violation.Constraint != "TS 29.002 §17.1.1: short-length" {
						t.Fatalf("MAP root with caller %s: %v", tracker.name, err)
					}
				} else if err != nil {
					t.Fatalf("generic root with caller %s: %v", tracker.name, err)
				}
			}
			if tracker.name == "MAP" {
				err := ValidateBERElement(structureWire(t, "318100"), tracker.options...)
				if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "generated MAP decoder") {
					t.Fatalf("standalone scan after alternating roots: %v", err)
				}
			}
		})
	}
}
