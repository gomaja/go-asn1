package ber

import (
	"errors"
	"testing"
)

func TestGeneratedEncodeOptionsRetainPathsAndStageReports(t *testing.T) {
	var reports ViolationLog
	options, finish := StageGeneratedEncodeReports([]EncodeOption{WithConstraintTolerance(&reports)})
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
	element, finishElement := StageGeneratedEncodeReports([]EncodeOption{WithConstraintTolerance(&reports)})
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
	var path *ConstraintError
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
