// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/preflight_path_test.go; SHA-256 2a68ee13a188ab9770215a3df52a490bd1cfc1436303cd3cbde2fbcd05c4d144.
package ber

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type testPreflightPath struct{ value string }

func (e testPreflightPath) Error() string       { return "diagnostic failure" }
func (e testPreflightPath) Unwrap() error       { return ErrInvalidValue }
func (e testPreflightPath) ASN1BERPath() string { return e.value }

func TestDiagnosePreflightPreservesFailureAndProbeScope(t *testing.T) {
	wire := []byte{3, 2, 8, 0x80}
	original := &ElementError{offset: 0, childIndexes: []int{2, 1}, cause: ErrInvalidValue}
	var captured []DecodeOption
	calls := 0
	err := DiagnosePreflight(original, wire, nil, "element", func(options []DecodeOption) error {
		calls++
		captured = options
		MarkPreflightTarget(ChildDecodeOptions(options, "element[2]"), "inside", wire)
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatalf("diagnostic preflight was not suppressed: %v", err)
		}
		return testPreflightPath{value: "element[2].inside"}
	})
	var located *ElementError
	var path interface{ ASN1BERPath() string }
	if calls != 1 || !errors.Is(err, ErrInvalidValue) || !errors.As(err, &located) || located != original ||
		!errors.As(err, &path) || path.ASN1BERPath() != "element[2].inside" {
		t.Fatalf("calls=%d diagnostic=%v", calls, err)
	}
	if err := ValidateBERElement(wire, captured...); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("diagnostic option outlived its callback: %v", err)
	}
	if !reflect.DeepEqual(located.ChildIndexes(), []int{2, 1}) || located.Offset() != 0 {
		t.Fatalf("preflight location changed: %#v", located)
	}
}

func TestDiagnosePreflightOpaquePosition(t *testing.T) {
	original := &ElementError{offset: 4, childIndexes: []int{1, 3}, cause: ErrInvalidValue}
	err := DiagnosePreflight(original, nil, nil, "element", func([]DecodeOption) error { return testWrongPreflightPath{} })
	var path interface{ ASN1BERPath() string }
	if !errors.As(err, &path) || path.ASN1BERPath() != "element[1].child[3]" {
		t.Fatalf("opaque position: %v", err)
	}
}

func TestDiagnosePreflightNamesOpaqueParent(t *testing.T) {
	wire := []byte{0x30, 6, 0x30, 4, 3, 2, 8, 0x80}
	original := &ElementError{offset: 4, childIndexes: []int{0, 0}, cause: ErrInvalidValue}
	err := DiagnosePreflight(original, wire, nil, "child", func(options []DecodeOption) error {
		MarkPreflightOpaque(options, "open-field", wire[2:], 6)
		return nil
	})
	var path interface{ ASN1BERPath() string }
	if !errors.As(err, &path) || path.ASN1BERPath() != "open-field.child[0]" {
		t.Fatalf("opaque field prefix: %v", err)
	}
	err = DiagnosePreflight(original, wire, nil, "child", func(options []DecodeOption) error {
		copied := append([]byte(nil), wire[2:]...)
		MarkPreflightOpaque(options, "unrelated", copied, len(copied))
		return nil
	})
	if !errors.As(err, &path) || path.ASN1BERPath() != "child[0].child[0]" {
		t.Fatalf("copied opaque value was guessed as the failing field: %v", err)
	}
	nested := append([]byte{0x30, 8}, wire...)
	nestedOriginal := &ElementError{offset: 6, childIndexes: []int{0, 0, 0}, cause: ErrInvalidValue}
	err = DiagnosePreflight(nestedOriginal, nested, nil, "element", func(options []DecodeOption) error {
		MarkPreflightOpaque(ChildDecodeOptions(options, "element[0]"), "open-field", nested[4:], 6)
		return nil
	})
	if !errors.As(err, &path) || path.ASN1BERPath() != "element[0].open-field.child[0]" {
		t.Fatalf("nested opaque field prefix: %v", err)
	}
}

func TestDiagnosePreflightProbePanicKeepsOriginalFailure(t *testing.T) {
	original := &ElementError{offset: 2, childIndexes: []int{0}, cause: ErrInvalidValue}
	err := DiagnosePreflight(original, nil, nil, "child", func([]DecodeOption) error {
		panic("malformed diagnostic input")
	})
	var located *ElementError
	var path interface{ ASN1BERPath() string }
	if !errors.As(err, &located) || located != original || !errors.As(err, &path) || path.ASN1BERPath() != "child[0]" {
		t.Fatalf("diagnostic panic changed rejection: %v", err)
	}
}

func TestDiagnosePreflightRootFailureNeedsNoProbe(t *testing.T) {
	original := &ElementError{offset: 0, cause: ErrInvalidValue}
	calls := 0
	err := DiagnosePreflight(original, []byte{3, 2, 8, 0x80}, nil, "child", func([]DecodeOption) error {
		calls++
		return nil
	})
	if calls != 0 || err != original {
		t.Fatalf("root failure changed: calls=%d error=%v", calls, err)
	}
}

func TestDiagnosePreflightEarlierSameSentinel(t *testing.T) {
	wire := []byte{0x30, 0x05, 0x04, 0x00, 0x22, 0x01, 0x00}
	original := &ElementError{offset: 4, childIndexes: []int{1}, cause: ErrInvalidTag}
	for _, kind := range []string{"strict", "tolerant"} {
		t.Run(kind, func(t *testing.T) {
			var options []DecodeOption
			if kind == "tolerant" {
				options = append(options, WithTolerance(new(ViolationLog)))
			}
			err := DiagnosePreflight(original, wire, options, "element", func(options []DecodeOption) error {
				// The diagnostic decoder encounters child 0 before the failing child.
				return testWrongPreflightPath{}
			})
			var path interface{ ASN1BERPath() string }
			var located *ElementError
			if !errors.Is(err, ErrInvalidTag) || !errors.As(err, &located) || located != original ||
				!errors.As(err, &path) || path.ASN1BERPath() != "element[1]" {
				t.Fatalf("wrong attribution: %v", err)
			}
		})
	}
}

func TestDiagnosePreflightMarksOnlyTargetIdentifier(t *testing.T) {
	wire := []byte{0x30, 0x05, 0x04, 0x00, 0x22, 0x01, 0x00}
	original := &ElementError{offset: 4, childIndexes: []int{1}, cause: ErrInvalidTag}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"earlier sibling", wire[2:], "element[1]"},
		{"copied target", append([]byte(nil), wire[4:]...), "element[1]"},
		{"actual target", wire[4:], "target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := DiagnosePreflight(original, wire, nil, "element", func(options []DecodeOption) error {
				MarkPreflightTarget(options, "target", tc.raw)
				return testWrongPreflightPath{}
			})
			var path interface{ ASN1BERPath() string }
			if !errors.As(err, &path) || path.ASN1BERPath() != tc.want {
				t.Fatalf("path=%v want %s", err, tc.want)
			}
		})
	}
}

func TestDiagnosePreflightElementIndex(t *testing.T) {
	wire := []byte{0x30, 0x05, 0x04, 0x00, 0x22, 0x01, 0x00}
	original := &ElementError{offset: 4, childIndexes: []int{1}, cause: ErrInvalidTag}
	err := DiagnosePreflight(original, wire, nil, "element", func(options []DecodeOption) error {
		MarkPreflightElement(options, 0, wire[2:])
		MarkPreflightElement(options, 1, wire[4:])
		return testWrongPreflightPath{}
	})
	var path interface{ ASN1BERPath() string }
	if !errors.As(err, &path) || path.ASN1BERPath() != "element[1]" {
		t.Fatalf("element index: %v", err)
	}
}

func TestPreflightElementLocatesOrdinaryConstraint(t *testing.T) {
	wire := []byte{0x30, 9, 0x04, 3, 0x11, 0x22, 0x33, 0x04, 2, 0xaa, 0xbb}
	for _, tolerant := range []bool{false, true} {
		var reports ViolationLog
		var options []DecodeOption
		if tolerant {
			options = append(options, WithTolerance(&reports))
		}
		options = LocateDecodedElement(wire, "Module.HLR-List", options)
		MarkPreflightElement(options, 0, wire[2:])
		MarkPreflightElement(options, 1, wire[7:])
		err := CheckDecodedLength(options, "element[1]", "SIZE (3..8)", 2)
		var got Violation
		if tolerant {
			if err != nil || len(reports.Snapshot()) != 1 {
				t.Fatalf("tolerant error=%v reports=%+v", err, reports.Snapshot())
			}
			got = reports.Snapshot()[0]
		} else {
			var failure *ValidationError
			if !errors.As(err, &failure) {
				t.Fatalf("strict error=%v", err)
			}
			got = failure.Violation
		}
		if got.Path != "element[1]" || got.Offset == nil || *got.Offset != 7 || !reflect.DeepEqual(got.ChildIndexes, []int{1}) {
			t.Fatalf("tolerant=%v location=%+v", tolerant, got)
		}
	}
}

func TestPreflightElementKeepsDistinctTolerantRecords(t *testing.T) {
	wire := []byte{0x30, 8, 0x04, 2, 0xaa, 0xbb, 0x04, 2, 0xcc, 0xdd}
	var reports ViolationLog
	options := LocateDecodedElement(wire, "Module.HLR-List", []DecodeOption{WithTolerance(&reports)})
	for index, offset := range []int{2, 6} {
		MarkPreflightElement(options, index, wire[offset:])
		if err := CheckDecodedLength(options, fmt.Sprintf("element[%d]", index), "SIZE (3..8)", 2); err != nil {
			t.Fatal(err)
		}
	}
	records := reports.Snapshot()
	if len(records) != 2 {
		t.Fatalf("records=%+v", records)
	}
	for index, record := range records {
		if record.Path != fmt.Sprintf("element[%d]", index) || record.Offset == nil || *record.Offset != 2+4*index || !reflect.DeepEqual(record.ChildIndexes, []int{index}) {
			t.Fatalf("record %d=%+v", index, record)
		}
	}
}

type testWrongPreflightPath struct{}

func (testWrongPreflightPath) Error() string       { return "earlier tag failure" }
func (testWrongPreflightPath) Unwrap() error       { return ErrInvalidTag }
func (testWrongPreflightPath) ASN1BERPath() string { return "wrong-field" }

func TestLargePreflightFailureDoesNotDecodeAgain(t *testing.T) {
	data := make([]byte, 1<<20)
	failure := &ElementError{offset: 900000, childIndexes: []int{1, 2}, cause: ErrResourceLimit}
	called := false
	err := DiagnosePreflight(failure, data, nil, "child", func([]DecodeOption) error { called = true; return nil })
	var located *ElementError
	if called || !errors.As(err, &located) || located != failure {
		t.Fatalf("probe=%v failure=%v", called, err)
	}
	var path interface{ ASN1BERPath() string }
	if !errors.As(err, &path) || path.ASN1BERPath() != "child[1].child[2]" {
		t.Fatal(err)
	}
}

func TestDiagnosePreflightNamesDescendantSegments(t *testing.T) {
	for _, tc := range []struct {
		name               string
		wire               []byte
		offset             int
		indexes            []int
		markOffset         int
		parent, leaf, want string
	}{
		{"assignment", []byte{0x24, 2, 5, 0}, 2, []int{0}, 0, "", "AddressString", "AddressString.child[0]"},
		{"choice", []byte{0xa0, 2, 5, 0}, 2, []int{0}, 0, "", "imsi", "imsi.child[0]"},
		{"nested segment", []byte{0x24, 4, 0x24, 2, 5, 0}, 4, []int{0, 0}, 0, "", "IMSI", "IMSI.child[0].child[0]"},
		{"component", []byte{0x30, 4, 0xa0, 2, 5, 0}, 4, []int{0, 0}, 2, "", "msisdn", "msisdn.child[0]"},
		{"collection", []byte{0x30, 4, 0x24, 2, 5, 0}, 4, []int{0, 0}, 2, "element[0]", "", "element[0].child[0]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &ElementError{offset: tc.offset, childIndexes: tc.indexes, cause: ErrInvalidTag}
			err := DiagnosePreflight(original, tc.wire, nil, "child", func(options []DecodeOption) error {
				if tc.name == "collection" {
					MarkPreflightElement(options, 0, tc.wire[tc.markOffset:])
				} else {
					if tc.parent != "" {
						options = ChildDecodeOptions(options, tc.parent)
					}
					MarkPreflightTarget(options, tc.leaf, tc.wire[tc.markOffset:])
				}
				return nil
			})
			var path interface{ ASN1BERPath() string }
			var located *ElementError
			if !errors.As(err, &path) || path.ASN1BERPath() != tc.want || !errors.As(err, &located) || located != original || !errors.Is(err, ErrInvalidTag) {
				t.Fatalf("diagnostic=%v want path %s and unchanged cause", err, tc.want)
			}
		})
	}
}

func TestDiagnosePreflightDescendantMarkerBoundaries(t *testing.T) {
	wire := []byte{0x30, 6, 0x24, 0, 0x24, 2, 5, 0}
	original := &ElementError{offset: 6, childIndexes: []int{1, 0}, cause: ErrInvalidTag}
	for _, raw := range [][]byte{wire[2:], wire[3:], append([]byte(nil), wire[4:]...)} {
		err := DiagnosePreflight(original, wire, nil, "child", func(options []DecodeOption) error {
			MarkPreflightTarget(options, "unrelated", raw)
			return nil
		})
		var path interface{ ASN1BERPath() string }
		if !errors.As(err, &path) || path.ASN1BERPath() != "child[1].child[0]" {
			t.Fatal(err)
		}
	}
	for _, size := range []int{64 << 10, 64<<10 + 1} {
		data := make([]byte, size)
		copy(data, []byte{0x24, 2, 5, 0})
		called := false
		err := DiagnosePreflight(&ElementError{offset: 2, childIndexes: []int{0}, cause: ErrInvalidTag}, data, nil, "child", func(options []DecodeOption) error {
			called = true
			MarkPreflightTarget(options, "AddressString", data)
			return nil
		})
		want := "child[0]"
		if size == 64<<10 {
			want = "AddressString.child[0]"
		}
		var path interface{ ASN1BERPath() string }
		if called != (size == 64<<10) || !errors.As(err, &path) || path.ASN1BERPath() != want {
			t.Fatalf("size=%d called=%v error=%v", size, called, err)
		}
	}
}

func TestDiagnosePreflightAncestorSearchIsLinear(t *testing.T) {
	for _, count := range []int{32, 256, 1024} {
		var contents []byte
		for range count {
			contents = append(contents, 4, 1, '1')
		}
		contents = append(contents, 0x24, 2, 5, 0)
		wire := append([]byte{0x30}, EncodeLength(len(contents))...)
		header := len(wire)
		wire = append(wire, contents...)
		original := ValidateBERElement(wire)
		visits := 0
		err := DiagnosePreflight(original, wire, nil, "child", func(options []DecodeOption) error {
			for index := range count + 1 {
				MarkPreflightElement(options, index, wire[header+3*index:])
			}
			visits = options[0].(preflightProbeOption).state.origin.ancestryVisits
			return nil
		})
		var path interface{ ASN1BERPath() string }
		t.Logf("elements=%d ancestry identifier visits=%d", count+1, visits)
		want := fmt.Sprintf("element[%d].child[0]", count)
		if !errors.As(err, &path) || path.ASN1BERPath() != want || visits > 2*count+4 {
			t.Fatalf("elements=%d visits=%d error=%v", count, visits, err)
		}
	}
}

func FuzzDiagnosePreflightAncestors(f *testing.F) {
	for _, wire := range [][]byte{{0x24, 2, 5, 0}, {0x30, 6, 0x24, 0, 0x24, 2, 5, 0}, {0x24, 3, 4, 2, '1'}, {0x24, 4, 4, 0x80, 0, 0}} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		options := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 16, MaxElements: 1024, MaxWork: 65536})}
		original := ValidateBERElement(data, options...)
		err := DiagnosePreflight(original, data, options, "child", func(options []DecodeOption) error {
			MarkPreflightTarget(options, "Value", data)
			for offset := 1; offset < len(data); offset++ {
				MarkPreflightTarget(options, "candidate", data[offset:])
			}
			return nil
		})
		if (err == nil) != (original == nil) {
			t.Fatal("diagnostic changed verdict")
		}
		var before, after *ElementError
		if errors.As(original, &before) != errors.As(err, &after) || before != after {
			t.Fatal("diagnostic changed located cause")
		}
		for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrInvalidLength, ErrUnexpectedElement, ErrExtraData, ErrInvalidValue, ErrResourceLimit} {
			if errors.Is(err, sentinel) != errors.Is(original, sentinel) {
				t.Fatal("diagnostic changed error class")
			}
		}
	})
}

func TestDiagnosePreflightContinuesPastTolerableFindings(t *testing.T) {
	wire := []byte{0x30, 7, 4, 0, 1, 1, 1, 0x22, 0}
	original := &ElementError{offset: 7, childIndexes: []int{2}, cause: ErrInvalidTag}
	for _, tolerant := range []bool{false, true} {
		t.Run(fmt.Sprint(tolerant), func(t *testing.T) {
			var log ViolationLog
			seed := []DecodeOption{WithTolerance(&log)}
			if err := CheckDecodedLength(seed, "seed", "SIZE (1..9)", 0); err != nil {
				t.Fatal(err)
			}
			options := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 7}), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 3})}
			if tolerant {
				options = append(options, WithTolerance(&log))
			}
			options = TrackMAPForm(ParentCollectionSizeDecodeOptions(ChildDecodeOptions(options, "outer")))
			before := log.Snapshot()
			configBefore, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			formBefore := *configBefore.form
			err = DiagnosePreflight(original, wire, options, "child", func(probe []DecodeOption) error {
				config, err := decodeOptions(probe)
				if err != nil {
					return err
				}
				if config.limits != configBefore.limits || config.diagnostics != configBefore.diagnostics || config.collectionSizeChecked != configBefore.collectionSizeChecked {
					t.Fatal("probe changed limits")
				}
				if err := CheckDecodedLength(probe, "earlier", "SIZE (1..9)", 0); err != nil {
					return err
				}
				if _, _, _, err := DecodeBoolean(wire[4:], probe...); err != nil {
					return err
				}
				MarkPreflightTarget(probe, "later", wire[7:])
				return ErrInvalidTag
			})
			var path interface{ ASN1BERPath() string }
			var located *ElementError
			if !errors.As(err, &path) || path.ASN1BERPath() != "outer.later" || !errors.As(err, &located) || located != original {
				t.Fatalf("diagnostic=%v", err)
			}
			configAfter, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, log.Snapshot()) || configBefore.form != configAfter.form || configBefore.tolerant != configAfter.tolerant || configBefore.violations != configAfter.violations || configBefore.limits != configAfter.limits || configBefore.diagnostics != configAfter.diagnostics || formBefore.preserve != configAfter.form.preserve || formBefore.mapSyntax != configAfter.form.mapSyntax {
				t.Fatal("probe changed caller state")
			}
			err = CheckDecodedLength(options, "after", "SIZE (1..9)", 0)
			if tolerant {
				if err != nil || len(log.Snapshot()) != len(before)+1 {
					t.Fatalf("tolerant caller changed: %v", err)
				}
			} else if err == nil || !reflect.DeepEqual(before, log.Snapshot()) {
				t.Fatalf("strict caller changed: %v", err)
			}
		})
	}
}

func TestDiagnosePreflightManyTolerableFindingsStayBounded(t *testing.T) {
	for _, count := range []int{64, 256, 768} {
		contents := make([]byte, 0, count*64+4)
		for range count {
			contents = append(contents, 4, 62)
			contents = append(contents, make([]byte, 62)...)
		}
		contents = append(contents, 0x24, 2, 5, 0)
		wire := append([]byte{0x30}, EncodeLength(len(contents))...)
		header := len(wire)
		wire = append(wire, contents...)
		original := ValidateBERElement(wire)
		visits, findings := 0, 0
		err := DiagnosePreflight(original, wire, nil, "child", func(options []DecodeOption) error {
			for index := range count + 1 {
				MarkPreflightElement(options, index, wire[header+64*index:])
				if index < count {
					if err := CheckDecodedLength(options, fmt.Sprintf("element[%d]", index), "SIZE (1)", 62); err != nil {
						return err
					}
					findings++
				}
			}
			visits = options[0].(preflightProbeOption).state.origin.ancestryVisits
			return nil
		})
		var path interface{ ASN1BERPath() string }
		if len(wire) >= 64<<10 || findings != count || visits > 2*count+4 || !errors.As(err, &path) || path.ASN1BERPath() != fmt.Sprintf("element[%d].child[0]", count) {
			t.Fatalf("bytes=%d findings=%d visits=%d error=%v", len(wire), findings, visits, err)
		}
		t.Logf("bytes=%d findings=%d ancestry visits=%d", len(wire), findings, visits)
	}
}

func TestDiagnosePreflightKeepsDiagnosticRecordLimit(t *testing.T) {
	wire := []byte{0x30, 6, 4, 0, 4, 0, 0x22, 0}
	original := &ElementError{offset: 6, childIndexes: []int{2}, cause: ErrInvalidTag}
	var stopped error
	err := DiagnosePreflight(original, wire, []DecodeOption{WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 1})}, "child", func(options []DecodeOption) error {
		for _, name := range []string{"first", "second"} {
			if stopped = CheckDecodedLength(options, name, "SIZE (1)", 0); stopped != nil {
				return stopped
			}
		}
		MarkPreflightTarget(options, "unreached", wire[6:])
		return nil
	})
	var path interface{ ASN1BERPath() string }
	if !errors.Is(stopped, ErrResourceLimit) || !errors.Is(err, ErrInvalidTag) || !errors.As(err, &path) || path.ASN1BERPath() != "child[2]" {
		t.Fatalf("stop=%v diagnostic=%v", stopped, err)
	}
}

func TestDiagnosePreflightChildLocationKeepsOuterCoordinates(t *testing.T) {
	// The invalid segment is at offset 10, child [0,1,0] of the outer
	// message, but at offset 8, child [1,0] of the inner value.
	outer := []byte{0x30, 11, 0x30, 9, 4, 2, 'a', 'b', 0x24, 3, 0x12, 1, 'x'}
	child := outer[2:]
	for _, tc := range []struct {
		name    string
		options []DecodeOption
		want    string
		offset  int
		indexes []int
	}{
		{"unbound", nil, "Inner.child[1].child[0]", 8, []int{1, 0}},
		{"child root", LocateDecodedElement(child, "Inner", nil), "Inner.child[1].child[0]", 8, []int{1, 0}},
		{"outer root", ChildDecodeOptions(LocateDecodedElement(outer, "Outer", nil), "inner"), "child[0].child[1].child[0]", 10, []int{0, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := ValidateBERElement(child, tc.options...)
			var before *ElementError
			if !errors.Is(original, ErrInvalidTag) || !errors.As(original, &before) || before.Offset() != tc.offset || !reflect.DeepEqual(before.ChildIndexes(), tc.indexes) {
				t.Fatalf("preflight location: %v", original)
			}
			calls := 0
			err := DiagnosePreflight(original, child, tc.options, "child", func(options []DecodeOption) error {
				calls++
				MarkPreflightTarget(options, "Inner", child)
				return nil
			})
			if calls != 1 {
				t.Fatalf("diagnostic callback ran %d times, want 1", calls)
			}
			var path interface{ ASN1BERPath() string }
			var after *ElementError
			if !errors.As(err, &path) || path.ASN1BERPath() != tc.want || !errors.As(err, &after) || after != before || !errors.Is(err, ErrInvalidTag) {
				t.Fatalf("diagnostic=%v want path %s and unchanged cause", err, tc.want)
			}
		})
	}
}

func TestDiagnosePreflightEmptyNameKeepsRootElementLabel(t *testing.T) {
	wire := []byte{0x30, 4, 0x24, 2, 5, 0}
	original := ValidateBERElement(wire)
	for _, name := range []string{"", "Values"} {
		t.Run(fmt.Sprintf("name=%q", name), func(t *testing.T) {
			err := DiagnosePreflight(original, wire, nil, "element", func(options []DecodeOption) error {
				MarkPreflightTarget(options, name, wire)
				return nil
			})
			want := "element[0].child[0]"
			if name != "" {
				want = "Values.child[0].child[0]"
			}
			var path interface{ ASN1BERPath() string }
			if !errors.As(err, &path) || path.ASN1BERPath() != want || !errors.Is(err, ErrInvalidTag) || !errors.Is(err, original) {
				t.Fatalf("diagnostic=%v want path %s and unchanged cause", err, want)
			}
		})
	}
}
