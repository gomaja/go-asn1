// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/finish_allocation_test.go; SHA-256 40b5435c02ab3d674d9d548068615a15a19981aec7aa102669e33096900d3abd.
package aper

import "testing"

func TestSuccessfulReportFinalizationDoesNotAllocate(t *testing.T) {
	state := ApplyDecodeOptions()
	allocations := testing.AllocsPerRun(100, func() {
		report, err := FinishDecode(state, nil)
		if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 0 {
			panic("successful report changed")
		}
	})
	if allocations != 0 {
		t.Fatalf("successful report finalization allocated %v times", allocations)
	}
}
