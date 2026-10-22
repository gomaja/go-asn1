// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_resolved_options_test.go; SHA-256 16869cfae93fb3291a02cca6cec624f5feb9da663257fe9027ed2fe5acb9cded.
package ber

import (
	"errors"
	"sync"
	"testing"
)

func TestGeneratedResolvedOptionsPreserveOverrideOrder(t *testing.T) {
	tracked := TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 7}), constraintPathOption("root")})
	for _, test := range []struct {
		name    string
		options []DecodeOption
		depth   int
		work    int
	}{
		{"tracked", tracked, 7, 16 << 20},
		{"before", append([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 3, MaxWork: 99})}, tracked...), 7, 99},
		{"after", append(append([]DecodeOption(nil), tracked...), WithDecodeLimits(DecodeLimits{MaxDepth: 3, MaxWork: 99})), 3, 99},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := decodeOptions(test.options)
			if err != nil || config.limits.MaxDepth != test.depth || config.limits.MaxWork != test.work {
				t.Fatalf("limits = %+v, error = %v", config.limits, err)
			}
			var constraint *ValidationError
			if err := CheckDecodedLength(ChildDecodeOptions(test.options, "field"), "leaf", "SIZE (2)", 1); !errors.As(err, &constraint) || constraint.Path != "root.field.leaf" {
				t.Fatalf("constraint path = %v", err)
			}
		})
	}
}

func TestGeneratedResolvedOptionsPreserveFailures(t *testing.T) {
	sentinel := errors.New("custom option refused")
	for _, test := range []struct {
		name    string
		options []DecodeOption
		want    string
	}{
		{"nil", []DecodeOption{nil}, "ber: invalid value encoding: nil BER decode option"},
		{"negative limit", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: -1})}, "ber: invalid value encoding: BER decode limits must be positive"},
		{"invalid path", []DecodeOption{constraintPathOption("bad.path")}, "ber: invalid value encoding: invalid BER constraint path component"},
		{"custom", []DecodeOption{decodeOptionFunc(func(*decodeConfig) error { return sentinel })}, "custom option refused"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tracked := TrackBERForm(test.options)
			_, err := OwnGeneratedBERInput([]byte{0x05, 0}, tracked)
			if err == nil || err.Error() != test.want {
				t.Fatalf("option failure = %v, want %q", err, test.want)
			}
			if test.name == "custom" && !errors.Is(err, sentinel) {
				t.Fatalf("custom cause lost: %v", err)
			}
		})
	}
	tracked := TrackBERForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: -1})})
	if err := ValidateDecodeOptions(append(tracked, WithDecodeLimits(DecodeLimits{MaxDepth: 5}))...); err != nil {
		t.Fatalf("later option did not repair invalid limit: %v", err)
	}
}

func TestGeneratedResolvedTrackerStagesIndependentCalls(t *testing.T) {
	var reports ViolationLog
	tracked := TrackBERForm([]DecodeOption{WithTolerance(&reports), constraintPathOption("root")})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			options, finish := StageDecodeReports(tracked)
			options = TrackBERForm(options)
			if BERNeedsPreservation(options) {
				t.Error("new root retained prior form")
			}
			MarkBERNonCanonical(options)
			if !BERNeedsPreservation(options) {
				t.Error("root form was not tracked")
			}
			if err := CheckDecodedLength(options, "leaf", "SIZE (2)", 1); err != nil {
				t.Error(err)
			}
			finish(i%2 == 0)
		})
	}
	wg.Wait()
	if BERNeedsPreservation(tracked) {
		t.Error("staged calls mutated caller tracker")
	}
	got := reports.Snapshot()
	if len(got) != 4 {
		t.Fatalf("committed reports = %d, want four", len(got))
	}
	for _, report := range got {
		if report.Path != "root.leaf" || report.ObservedLength == nil || *report.ObservedLength != 1 {
			t.Fatalf("report = %+v", report)
		}
	}
}

func TestGeneratedResolvedTrackerCopiesCallerOptions(t *testing.T) {
	options := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: 99}), constraintPathOption("root")}
	tracked := TrackBERForm(options)
	options[0] = WithDecodeLimits(DecodeLimits{MaxWork: 1})
	options[1] = constraintPathOption("changed")
	config, err := decodeOptions(tracked)
	if err != nil || config.limits.MaxWork != 99 {
		t.Fatalf("tracked limits changed: %+v, %v", config.limits, err)
	}
	if path := qualifyConstraintPath(tracked, "leaf"); path != "root.leaf" {
		t.Fatalf("tracked path = %q", path)
	}
}

func TestGeneratedResolvedTrackerPreservesPreflightPath(t *testing.T) {
	wire := []byte{0x30, 0x02, 0x02, 0x00}
	options := TrackBERForm([]DecodeOption{constraintPathOption("root")})
	err := ValidateBERElement(wire, options...)
	if err == nil {
		t.Fatal("empty INTEGER accepted")
	}
	err = DiagnosePreflight(err, wire, options, "child", func(probe []DecodeOption) error {
		probe, finish := StageDecodeReports(probe)
		defer finish(false)
		probe = TrackBERForm(probe)
		MarkPreflightTarget(probe, "leaf", wire[2:])
		return nil
	})
	var path interface{ ASN1BERPath() string }
	if !errors.As(err, &path) || path.ASN1BERPath() != "root.leaf" {
		t.Fatalf("preflight path = %v", err)
	}
}

func TestGeneratedResolvedUnstagedToleranceKeepsIndependentBudgets(t *testing.T) {
	var reports ViolationLog
	options := TrackBERForm([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 1})})
	for _, field := range []string{"first", "second"} {
		if err := CheckDecodedValue(options, field, "test constraint", "bad"); err != nil {
			t.Fatalf("independent %s call exhausted another call's budget: %v", field, err)
		}
	}
	if got := len(reports.Snapshot()); got != 2 {
		t.Fatalf("independent calls reported %d findings, want two", got)
	}
}

func TestGeneratedContextResolutionRejectsFabricatedInvalidContexts(t *testing.T) {
	valid := decodeConfig{limits: DefaultDecodeLimits(), diagnostics: DefaultDiagnosticLimits()}
	source := &validatedBERSource{light: true, owned: []byte{0x05, 0x00}}
	badLimits, badDiagnostics, badDecimal := valid, valid, valid
	badLimits.limits.MaxDepth = -1
	badDiagnostics.diagnostics.MaxRecords = -1
	badDecimal.limits.MaxRealDecimalDigits = -1
	for _, test := range []struct {
		name    string
		context *generatedDecodeOption
		want    string
	}{
		{"nil", nil, "invalid generated BER decode context"},
		{"no source", &generatedDecodeOption{config: valid}, "invalid generated BER decode context"},
		{"unowned source", &generatedDecodeOption{source: &validatedBERSource{}, config: valid}, "invalid generated BER decode context"},
		{"negative depth", &generatedDecodeOption{source: source, config: badLimits}, "BER decode limits must be positive"},
		{"negative diagnostic budget", &generatedDecodeOption{source: source, config: badDiagnostics}, "BER diagnostic limits must be positive"},
		{"negative decimal budget", &generatedDecodeOption{source: source, config: badDecimal}, "REAL decimal digit limit must be nonnegative"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := []DecodeOption{test.context}
			want := "ber: invalid value encoding: " + test.want
			if err := ValidateDecodeOptions(options...); err == nil || err.Error() != want || !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("invalid context = %v, want %q", err, want)
			}
			if _, _, _, err := DecodeTLV([]byte{0x05, 0x00}, options...); err == nil || err.Error() != want {
				t.Fatalf("invalid context wire entry = %v, want %q", err, want)
			}
		})
	}
	invalid := &generatedDecodeOption{source: source, config: badLimits}
	if err := ValidateDecodeOptions(invalid, WithDecodeLimits(DecodeLimits{MaxDepth: 7})); err != nil {
		t.Fatalf("later limit did not repair fabricated context: %v", err)
	}
}

func TestDefaultDecodeConfigValuesRemainIndependent(t *testing.T) {
	first, err := decodeOptions(nil)
	if err != nil || first.limits != DefaultDecodeLimits() || first.diagnostics != DefaultDiagnosticLimits() {
		t.Fatalf("default policy = %+v, %v", first, err)
	}
	first.limits.MaxWork = 1
	first.diagnostics.MaxRecords = 1
	second, err := decodeOptions(nil)
	if err != nil || second.limits != DefaultDecodeLimits() || second.diagnostics != DefaultDiagnosticLimits() {
		t.Fatalf("default policy changed with another call: %+v, %v", second, err)
	}
}

func TestGeneratedChildOptionsUseOneAllocation(t *testing.T) {
	for _, mode := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		options := TrackBERForm([]DecodeOption{mode})
		owned, err := OwnGeneratedBERInput([]byte{0x30, 2, 5, 0}, options)
		if err != nil {
			t.Fatal(err)
		}
		_, options, err = PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		var retained []DecodeOption
		allocations := testing.AllocsPerRun(1000, func() { retained = ChildDecodeOptions(options, "child") })
		var violation *ValidationError
		if err := CheckDecodedValue(retained, "leaf", "test constraint", "bad"); !errors.As(err, &violation) || violation.Path != "child.leaf" {
			t.Fatalf("retained path: %v", err)
		}
		if allocations > 1 {
			t.Fatalf("child options allocated %.0f objects, want at most one", allocations)
		}
	}
}

func TestTCAPRootResolvesOriginalOptionsOnce(t *testing.T) {
	for _, mode := range []DecodeOption{nil, ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		applications := 0
		options := []DecodeOption{decodeOptionFunc(func(config *decodeConfig) error { applications++; config.limits.MaxWork = 256; return nil })}
		if mode != nil {
			options = append(options, mode)
		}
		options, finish := StageDecodeReports(options)
		defer finish(false)
		options = TrackTCAPForm(options, "Begin", "TCAPMessages", "Begin")
		owned, err := OwnGeneratedBERInput([]byte{0x62, 3, 0x48, 1, 1}, options)
		if err != nil {
			t.Fatal(err)
		}
		owned, options, err = PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(owned, "TCAPMessages.Begin", options)
		if _, _, _, err := DecodeTLV(owned, options...); err != nil {
			t.Fatal(err)
		}
		if applications != 1 {
			t.Fatalf("TCAP root applied original options %d times, want once", applications)
		}
	}
}

func TestTCAPChildProfileOptionsUseOneAllocation(t *testing.T) {
	options := TrackTCAPForm(nil, "Begin", "TCAPMessages", "Begin")
	owned, err := OwnGeneratedBERInput([]byte{0x62, 3, 0x48, 1, 1}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	var child []DecodeOption
	allocations := testing.AllocsPerRun(1000, func() { child = TrackTCAPForm(options, "End", "TCAPMessages", "End") })
	original, _ := decodeOptions(options)
	changed, err := decodeOptions(child)
	if err != nil || original.profileType != "Begin" || changed.profileType != "End" || !changed.profileNested || changed.profileSource != "TCAPMessages.Begin" {
		t.Fatalf("profile sharing changed policy: %+v, %+v, %v", original, changed, err)
	}
	if allocations > 1 {
		t.Fatalf("child profile allocated %.0f objects, want at most one", allocations)
	}
}
