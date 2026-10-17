// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/stage_fast_path_test.go; SHA-256 80202987ac3f8b983df5640e341205ce0f56a717303e366500603308e82cf610.
package ber

import (
	"testing"
)

var (
	stagedDecodeOptionsSink []DecodeOption
	stagedEncodeOptionsSink []EncodeOption
	stagedFinishSink        func(bool)
)

// A generated codec stages reports at each nested value, even when its caller
// did not request tolerance. Without tolerance the stage only copies the
// options, so it allocates once for a nonempty list and never for an empty one.
func TestReportStageWithoutToleranceAllocatesOnlyTheCopy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		decode []DecodeOption
		encode []EncodeOption
		want   float64
	}{
		{"empty", nil, nil, 0},
		{"nonempty", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 16})}, []EncodeOption{WithoutBERReplay()}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(1000, func() {
				stagedDecodeOptionsSink, stagedFinishSink = StageDecodeReports(tc.decode)
				stagedFinishSink(true)
			}); got != tc.want {
				t.Errorf("decode stage allocated %.1f times, want %.0f", got, tc.want)
			}
			if got := testing.AllocsPerRun(1000, func() {
				stagedEncodeOptionsSink, stagedFinishSink = StageEncodeReports(tc.encode)
				stagedFinishSink(true)
			}); got != tc.want {
				t.Errorf("encode stage allocated %.1f times, want %.0f", got, tc.want)
			}
		})
	}
}

// Staging returns an independent snapshot with or without tolerance: editing
// the caller's slice afterwards must not change the staged paths, limits or
// replay policy.
func TestStrictStageSnapshotsOptions(t *testing.T) {
	decode := []DecodeOption{constraintPathOption("before")}
	staged, done := StageDecodeReports(decode)
	decode[0] = constraintPathOption("after")
	if got := qualifyConstraintPath(staged, "field"); got != "before.field" {
		t.Errorf("decode staged path = %s, want before.field", got)
	}
	done(true)
	encode := []EncodeOption{constraintPathOption("before")}
	stagedEncode, finish := StageEncodeReports(encode)
	encode[0] = constraintPathOption("after")
	if got := qualifyConstraintPath(stagedEncode, "field"); got != "before.field" {
		t.Errorf("encode staged path = %s, want before.field", got)
	}
	finish(true)

	limits := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 2})}
	stagedLimits, doneLimits := StageDecodeReports(limits)
	limits[0] = WithDecodeLimits(DecodeLimits{MaxDepth: 3})
	if config, err := decodeOptions(stagedLimits); err != nil || config.limits.MaxDepth != 2 {
		t.Errorf("staged depth = %d, err %v, want 2", config.limits.MaxDepth, err)
	}
	doneLimits(true)
	replay := []EncodeOption{WithoutBERReplay()}
	stagedReplay, finishReplay := StageEncodeReports(replay)
	replay[0] = constraintPathOption("field")
	if BERReplayEnabled(stagedReplay) {
		t.Error("staged WithoutBERReplay was replaced by a later edit of the caller's slice")
	}
	finishReplay(true)
}
