// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/staged_depth_test.go; SHA-256 ed22fed7f1ac335e4169f1669f91b60c42d44375d6f26f310c1d4abec8f4b25b.
package ber

import "testing"

func TestNestedStageKeepsDeeperUTF8Location(t *testing.T) {
	wire := structureWire(t, "3009300706022a030c01ff")
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	if err := ValidateBERElement(wire, options...); err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(wire, "Module.Container", options)
	inner, finishInner := StageDecodeReports(ChildDecodeOptions(options, "private"))
	if err := ValidateBERElement(wire[2:], inner...); err != nil {
		t.Fatal(err)
	}
	_ = LocateDecodedElement(wire[2:], "Module.Private", inner)
	finishInner(true)
	finish(true)
	got := reports.Snapshot()
	if len(got) != 1 || got[0].Path != "private.child[1]" || got[0].Source != "Module.Private" || got[0].Offset == nil || *got[0].Offset != 8 {
		t.Fatalf("nested location: %+v", got)
	}
}
