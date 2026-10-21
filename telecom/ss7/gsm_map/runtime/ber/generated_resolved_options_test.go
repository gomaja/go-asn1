// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_resolved_options_test.go; SHA-256 1a7a171a9ad8d43017cc7c648d4750299db3c976998d0a6217e710e649b8104a.
package ber

import (
	"errors"
	"sync"
	"testing"
)

func TestGeneratedDecodeResolvesOriginalOptionsOnce(t *testing.T) {
	for _, mode := range []struct {
		name   string
		option DecodeOption
	}{{"adaptive", nil}, {"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()}} {
		t.Run(mode.name, func(t *testing.T) {
			applications := 0
			options := []DecodeOption{decodeOptionFunc(func(config *decodeConfig) error {
				applications++
				config.limits.MaxWork = 256
				return nil
			}), constraintPathOption("root")}
			if mode.option != nil {
				options = append(options, mode.option)
			}
			options, finish := StageDecodeReports(options)
			defer finish(false)
			options = TrackBERForm(options)
			owned, err := OwnGeneratedBERInput([]byte{0x30, 0x03, 0x04, 0x01, 'A'}, options)
			if err != nil {
				t.Fatal(err)
			}
			owned, options, err = PrepareGeneratedBERInput(owned, options)
			if err != nil {
				t.Fatal(err)
			}
			options = LocateDecodedElement(owned, "test source", options)
			child := []DecodeOption{ChildDecodeContext(options, "child")}
			child, commit := StageDecodeReports(child)
			defer commit(false)
			child = TrackBERForm(child)
			childInput, err := OwnGeneratedBERInput(owned[2:], child)
			if err != nil {
				t.Fatal(err)
			}
			childInput, child, err = PrepareGeneratedBERInput(childInput, child)
			if err != nil {
				t.Fatal(err)
			}
			child = LocateDecodedElement(childInput, "child source", child)
			var constraint *ValidationError
			if err := CheckDecodedLength(child, "leaf", "SIZE (2)", 1); !errors.As(err, &constraint) || constraint.Path != "root.child.leaf" {
				t.Fatalf("child constraint = %v", err)
			}
			t.Logf("original decode option applications: %d", applications)
			if applications != 1 {
				t.Fatalf("original options applied %d times, want once", applications)
			}
		})
	}
}

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

func TestGeneratedContextResolutionPreservesInvalidChildErrors(t *testing.T) {
	for _, mode := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		options := TrackBERForm([]DecodeOption{mode})
		owned, err := OwnGeneratedBERInput([]byte{0x05, 0x00}, options)
		if err != nil {
			t.Fatal(err)
		}
		_, options, err = PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range [][]DecodeOption{
			{ChildDecodeContext(options, "")},
			{ChildDecodeContext(options, "bad.path")},
			{ChildDecodeIndexContext(options, -1)},
			ChildDecodeOptions(options, ""),
			ChildDecodeOptions(options, "bad.path"),
			{ParentCollectionSizeDecodeContext(options, "bad.path")},
			ParentCollectionSizeDecodeOptions([]DecodeOption{ChildDecodeIndexContext(options, -1)}),
			{ChildDecodeContext(nil, "bad.path")},
			{ChildDecodeIndexContext(nil, -1)},
		} {
			if err := ValidateDecodeOptions(child...); err == nil || err.Error() != "ber: invalid value encoding: invalid BER constraint path component" {
				t.Fatalf("invalid child = %v", err)
			}
		}
		if err := ValidateDecodeOptions(append(options, WithDecodeLimits(DecodeLimits{MaxDepth: -1}))...); err == nil || err.Error() != "ber: invalid value encoding: BER decode limits must be positive" {
			t.Fatalf("invalid appended limit = %v", err)
		}
		if err := ValidateDecodeOptions(append([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: -1})}, options...)...); err != nil {
			t.Fatalf("context did not replace preceding limits: %v", err)
		}
		if err := ValidateDecodeOptions(append(append([]DecodeOption(nil), options...), WithDecodeLimits(DecodeLimits{MaxDepth: -1}), WithDecodeLimits(DecodeLimits{MaxDepth: 7}))...); err != nil {
			t.Fatalf("later option did not repair appended limits: %v", err)
		}
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

func TestGeneratedChildOptionsRetainedSliceUsesOneAllocation(t *testing.T) {
	for _, mode := range []struct {
		name   string
		option DecodeOption
	}{{"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()}} {
		t.Run(mode.name, func(t *testing.T) {
			options := TrackBERForm([]DecodeOption{mode.option})
			owned, err := OwnGeneratedBERInput([]byte{0x30, 2, 5, 0}, options)
			if err != nil {
				t.Fatal(err)
			}
			_, options, err = PrepareGeneratedBERInput(owned, options)
			if err != nil {
				t.Fatal(err)
			}
			var retained []DecodeOption
			allocations := testing.AllocsPerRun(1000, func() {
				retained = ChildDecodeOptions(options, "child")
			})
			var violation *ValidationError
			if err := CheckDecodedValue(retained, "leaf", "test constraint", "bad"); !errors.As(err, &violation) || violation.Path != "child.leaf" {
				t.Fatalf("retained child path = %v", err)
			}
			composed := testing.Benchmark(func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					retained = ParentCollectionSizeDecodeOptions(ChildDecodeOptions(options, "child"))
				}
			})
			t.Logf("retained=%.0f composed=%d composed_bytes=%d", allocations, composed.AllocsPerOp(), composed.AllocedBytesPerOp())
			ceiling := map[string]struct{ allocations, bytes int64 }{"light": {3, 976}, "proof": {3, 976}}[mode.name]
			if composed.AllocsPerOp() > ceiling.allocations || composed.AllocedBytesPerOp() > ceiling.bytes {
				t.Fatalf("composed child options exceed base: allocations=%d bytes=%d, want at most %d and %d", composed.AllocsPerOp(), composed.AllocedBytesPerOp(), ceiling.allocations, ceiling.bytes)
			}
			if allocations > 1 {
				t.Fatalf("retained child options allocated %.0f times, want at most one", allocations)
			}
		})
	}
}
