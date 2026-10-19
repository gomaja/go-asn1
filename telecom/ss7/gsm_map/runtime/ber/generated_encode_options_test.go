// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_encode_options_test.go; SHA-256 cbb67af47d1ca1310c6b64426600b23055543b6ee6b3850d1e76140cc531698f.
package ber

import (
	"errors"
	"testing"
)

func TestGeneratedEncodeOptionsRetainPathsAndStageReports(t *testing.T) {
	var reports ViolationLog
	options, finish := StageGeneratedEncodeReports([]EncodeOption{WithTolerance(&reports)})
	child, finishChild := StageGeneratedEncodeReports(ChildGeneratedEncodeOptions(options, "outer"))
	child = ChildGeneratedEncodeOptions(child, "inner")
	if err := CheckEncodedValue(child, "leaf", "(1)", "2"); err != nil {
		t.Fatal(err)
	}
	finishChild(true)
	if got := len(reports.Snapshot()); got != 0 {
		t.Fatalf("child committed staged reports: %d", got)
	}
	finish(true)
	got := reports.Snapshot()
	if len(got) != 1 || got[0].Path != "outer.inner.leaf" {
		t.Fatalf("staged reports: %+v", got)
	}
	element, finishElement := StageGeneratedEncodeReports([]EncodeOption{WithTolerance(&reports)})
	element = ChildGeneratedElementEncodeOptions(element, 7)
	if err := CheckEncodedValue(element, "leaf", "(1)", "2"); err != nil {
		t.Fatal(err)
	}
	finishElement(true)
	got = reports.Snapshot()
	if len(got) != 2 || got[1].Path != "element[7].leaf" {
		t.Fatalf("element report path: %+v", got)
	}
	strict, _ := StageGeneratedEncodeReports(nil)
	strict = ChildGeneratedEncodeOptions(strict, "outer")
	strict = ChildGeneratedEncodeOptions(strict, "inner")
	var path *ValidationError
	if err := CheckEncodedValue(strict, "leaf", "(1)", "2"); !errors.As(err, &path) || path.Path != "leaf" {
		t.Fatalf("strict path: %v", err)
	}
}

func TestGeneratedEncodeOptionsAllocationIsLinear(t *testing.T) {
	measure := func(depth int) int64 {
		result := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				var walk func(int, []EncodeOption)
				walk = func(level int, options []EncodeOption) {
					options, finish := StageGeneratedEncodeReports(options)
					defer finish(true)
					if err := ValidateEncodeOptions(options...); err != nil {
						b.Fatal(err)
					}
					if level > 1 {
						walk(level-1, ChildGeneratedEncodeOptions(options, "next"))
					}
				}
				walk(depth, []EncodeOption{WithoutBERReplay()})
			}
		})
		return result.AllocedBytesPerOp()
	}
	small, large := measure(64), measure(128)
	if large > 3*small || large > 256*128 {
		t.Fatalf("encode options allocate quadratically: depth 64=%d, 128=%d", small, large)
	}
}

func TestGeneratedEncodeMarkerValidationDoesNotAllocate(t *testing.T) {
	options := []EncodeOption{generatedEncodeMarker{}}
	allocations := testing.AllocsPerRun(100, func() {
		if err := ValidateEncodeOptions(options...); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("generated marker validation allocated %g times; want 0", allocations)
	}
}

func TestGeneratedEncodeWithoutOptionsAllocationBound(t *testing.T) {
	result := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			options, finish := StageGeneratedEncodeReports(nil)
			if err := ValidateEncodeOptions(options...); err != nil {
				b.Fatal(err)
			}
			finish(true)
		}
	})
	if result.AllocsPerOp() > 1 || result.AllocedBytesPerOp() > 16 {
		t.Fatalf("staging without caller options: %d allocations, %d bytes; want at most 1 and 16", result.AllocsPerOp(), result.AllocedBytesPerOp())
	}
}

func TestGeneratedEncodeWithoutOptionsIsolatesSiblings(t *testing.T) {
	options, finish := StageGeneratedEncodeReports(nil)
	defer finish(true)
	first := ParentGeneratedCollectionSizeEncodeOptions(options)
	second := append(options, WithoutBERReplay())
	firstConfig, err := encodeOptions(first)
	if err != nil || !firstConfig.collectionSizeChecked || firstConfig.noReplay {
		t.Fatalf("sibling changed first options: %+v, %v", firstConfig, err)
	}
	secondConfig, err := encodeOptions(second)
	if err != nil || secondConfig.collectionSizeChecked || !secondConfig.noReplay {
		t.Fatalf("first changed sibling options: %+v, %v", secondConfig, err)
	}
	if err := ValidateEncodeOptions(append(options, nil)...); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid child option accepted: %v", err)
	}
}

func TestGeneratedChildReplayTracksRetainedViolationsWithoutComparator(t *testing.T) {
	type value struct{ Node *ReplayNode }
	for _, tc := range []struct {
		name             string
		prior, violation bool
	}{
		{"clean", false, false}, {"prior-report", true, false}, {"violation", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reports ViolationLog
			if tc.prior {
				if err := CheckDecodedValue([]DecodeOption{WithTolerance(&reports)}, "prior", "(1)", "2"); err != nil {
					t.Fatal(err)
				}
			}
			options, commit := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
			if tc.violation {
				if err := CheckDecodedValue(options, "current", "(1)", "2"); err != nil {
					t.Fatal(err)
				}
			}
			config, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			wire := []byte{4, 1, 'A'}
			state := &ReplayState{nodeCount: 1}
			node := &ReplayNode{state: state, original: wire}
			state.root = node
			context := &generatedDecodeOption{source: &validatedBERSource{owned: wire, replay: state}, config: config}
			decoded := &value{Node: node}
			encode := func(v *value, options ...EncodeOption) ([]byte, error) {
				return PreserveEncodedBERNode([]byte{4, 1, 'A'}, v.Node, options), nil
			}
			if err := CompleteGeneratedBERDecode([]DecodeOption{context}, decoded, encode); err != nil {
				t.Fatal(err)
			}
			if state.decodeTolerant != tc.violation {
				t.Errorf("retained violation = %v, want %v", state.decodeTolerant, tc.violation)
			}
			_, replay := ReplayGeneratedBERNode(node, []EncodeOption{replayModeOption{state: state, unchanged: map[*ReplayNode]bool{node: true}}})
			if replay == tc.violation {
				t.Errorf("child replay = %v, retained violation %v", replay, tc.violation)
			}
			commit(true)
		})
	}
}

func TestRetainedViolationDisablesStrictEnvelopeReplay(t *testing.T) {
	for _, retained := range []bool{false, true} {
		state := &ReplayState{decodeTolerant: retained}
		for _, tolerant := range []bool{false, true} {
			opts := []EncodeOption{replayModeOption{state: state, rebuildChildren: retained}}
			if tolerant {
				opts = append(opts, WithTolerance(new(ViolationLog)))
			}
			if got, want := BERReplayEnabled(opts), !retained || tolerant; got != want {
				t.Errorf("retained %v tolerant %v: got %v want %v", retained, tolerant, got, want)
			}
		}
	}
}
