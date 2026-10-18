// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_encode_options_test.go; SHA-256 2cc8cd61302acad57d1d5644a25ff1b41bc8594347c483c875478855d82365c3.
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
