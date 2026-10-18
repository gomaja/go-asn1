// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/preflight_path_test.go; SHA-256 e9bc74f34a9ec52f4a1cb0fd3cf8ad51c8b9dcb94e2facc79f607b3263e0bf06.
package ber

import (
	"errors"
	"reflect"
	"testing"
)

type testPreflightPath struct{ value string }

func (e testPreflightPath) Error() string { return "diagnostic failure" }

func (e testPreflightPath) Unwrap() error { return ErrInvalidValue }

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

type testWrongPreflightPath struct{}

func (testWrongPreflightPath) Error() string { return "earlier tag failure" }

func (testWrongPreflightPath) Unwrap() error { return ErrInvalidTag }

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
