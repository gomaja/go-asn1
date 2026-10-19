// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque_test.go; SHA-256 de7c52a8fd3946f990964685f56e83c85c884c5381f7858eae62503d1cf1f32e.
package ber

import (
	"bytes"
	"errors"
	"testing"
)

func TestFreshOpaqueElement(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wire      []byte
		canonical bool
	}{
		{"NULL", []byte{5, 0}, true},
		{"unknown implicit", []byte{0x9e, 1, 0xff}, true},
		{"nonminimal length", []byte{5, 0x81, 0}, false},
		{"indefinite", []byte{0x30, 0x80, 5, 0, 0, 0}, false},
		{"nonminimal integer", []byte{2, 2, 0, 1}, false},
		{"two elements", []byte{5, 0, 5, 0}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.wire)
			for _, tolerant := range []bool{false, true} {
				options := []EncodeOption{WithoutBERReplay()}
				var reports ViolationLog
				if tolerant {
					options = append(options, WithTolerance(&reports))
				}
				err := CheckBEROpaqueElement(tc.wire, options...)
				if (err == nil) != tc.canonical {
					t.Fatalf("canonical=%t: %v", tc.canonical, err)
				}
				if err != nil && !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("missing error identity: %v", err)
				}
				if !bytes.Equal(original, tc.wire) || len(reports.Snapshot()) != 0 {
					t.Fatal("opaque check changed input or reports")
				}
			}
		})
	}
	if err := CheckBEROpaqueElement([]byte{5, 0}, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid option: %v", err)
	}
}

// X.690 (02/2021) §8.23.10 applies to retained open values and unknown
// extension additions just as it does to a typed UTF8String.
func TestOpaqueReplayValidatesRetainedUTF8(t *testing.T) {
	for _, wire := range [][]byte{
		{0x0c, 1, 0xff},
		{0x30, 3, 0x0c, 1, 0xff},
	} {
		if err := CheckBEROpaqueElement(wire); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("strict accepted %x: %v", wire, err)
		}
		var reports ViolationLog
		if err := CheckBEROpaqueElement(wire, WithTolerance(&reports)); err != nil {
			t.Fatalf("tolerant %x: %v", wire, err)
		}
		got := reports.Snapshot()
		if len(got) != 1 || got[0].Rule.Document != "ITU-T X.690" || got[0].Rule.Clause != "8.23.10" {
			t.Fatalf("tolerant %x reports %+v", wire, got)
		}
	}
	if err := CheckBEROpaqueElement([]byte{5, 0x81, 0}); err != nil {
		t.Fatalf("valid noncanonical BER replay: %v", err)
	}
}

func TestOpaqueEncodeReportUsesComponentIdentityWithoutWireCoordinates(t *testing.T) {
	for _, wire := range [][]byte{{0x0c, 1, 0xff}, {0x0c, 2, 0xff, 0xff}} {
		var reports ViolationLog
		options := EncodeSource(ChildEncodeOptions([]EncodeOption{WithTolerance(&reports)}, "extType"), "Module.PrivateExtension.extType")
		if err := CheckBEROpaqueElement(wire, options...); err != nil {
			t.Fatal(err)
		}
		got := reports.Snapshot()
		if len(got) != len(wire)-2 {
			t.Fatalf("opaque encode records: %+v", got)
		}
		for _, record := range got {
			if record.Path != "extType" || record.Source != "Module.PrivateExtension.extType" || record.Rule.Clause != "8.23.10" || record.ObservedValue != "ff" || record.Offset != nil || record.OctetOffset != nil || len(record.ChildIndexes) != 0 {
				t.Fatalf("opaque encode record: %+v", record)
			}
		}
	}
}

// Successful checks do not construct a diagnostic log. Stage the outer option
// once, just as generated codecs do before calling nested runtime checks.
func TestValidOpaqueToleranceHasNoDiagnosticAllocations(t *testing.T) {
	wire := []byte{12, 1, 'a'}
	var reports ViolationLog
	options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
	defer finish(false)
	strict := testing.AllocsPerRun(100, func() {
		if err := CheckBEROpaqueElement(wire); err != nil {
			panic(err)
		}
	})
	tolerant := testing.AllocsPerRun(100, func() {
		if err := CheckBEROpaqueElement(wire, options...); err != nil {
			panic(err)
		}
	})
	if strict != tolerant {
		t.Fatalf("valid opaque allocations: strict %.0f, tolerant %.0f", strict, tolerant)
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("valid opaque value reported a violation")
	}
}
