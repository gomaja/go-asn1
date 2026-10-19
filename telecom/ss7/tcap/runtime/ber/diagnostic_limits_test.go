// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/diagnostic_limits_test.go; SHA-256 094c24ae0b3066d1c09083165e064897c9ff402a4e671288f29a6b6b559c4e3f.
package ber

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"strings"
	"testing"
)

func TestBERDiagnosticBudgetSharedAcrossFields(t *testing.T) {
	var reports ViolationLog
	option := WithTolerance(&reports)
	for range 2 {
		options, finish := StageDecodeReports([]DecodeOption{option, WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 2})})
		for _, name := range []string{"first", "second", "third"} {
			child, childFinish := StageDecodeReports(ChildDecodeOptions(options, name))
			err := CheckDecodedValue(child, "", "(0)", "1")
			childFinish(err == nil)
			if name == "third" {
				if !errors.Is(err, ErrResourceLimit) {
					t.Fatalf("field budget reset: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
		finish(false)
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed operations published reports")
	}
	// Separate direct calls each get the whole budget, even with a reused option.
	for range 2 {
		_, _, err := DecodeString([]byte{12, 2, 255, 254}, tag.TagUTF8String, option, WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 2}))
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(reports.Snapshot()) != 4 {
		t.Fatal("diagnostic budget leaked between direct operations")
	}
}

func TestBERObservedValuesAreBoundedAndIndependent(t *testing.T) {
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxObservedBytes: 2 * MaxObservedValueBytes})})
	first := strings.Repeat("A", 4<<20) + "1"
	second := first[:len(first)-1] + "2"
	for _, observation := range []string{first, first, second} {
		if err := CheckDecodedValue(options, "text", "(0)", observation); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckDecodedValue(options, "other", "(0)", "x"); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("observed-byte overflow: %v", err)
	}
	finish(false)
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed byte-budget stage published reports")
	}
	config, err := decodeOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	got := config.violations.Snapshot()
	if len(got) != 2 {
		t.Fatalf("long values with distinct tails collapsed: %+v", got)
	}
	for _, record := range got {
		if len(record.ObservedValue) != MaxObservedValueBytes || record.ObservedValueLength != len(first) {
			t.Fatalf("uncapped observation: length %d, true length %d", len(record.ObservedValue), record.ObservedValueLength)
		}
	}
}

func TestBERDiagnosticLimitDefaultsAndValidation(t *testing.T) {
	for _, limits := range []DiagnosticLimits{{}, {MaxRecords: 1}, {MaxObservedBytes: 1}, {MaxRecords: 1, MaxObservedBytes: 1}} {
		config, err := decodeOptions([]DecodeOption{WithDiagnosticLimits(limits)})
		if err != nil {
			t.Fatal(err)
		}
		want := DefaultDiagnosticLimits()
		if limits.MaxRecords != 0 {
			want.MaxRecords = limits.MaxRecords
		}
		if limits.MaxObservedBytes != 0 {
			want.MaxObservedBytes = limits.MaxObservedBytes
		}
		if config.diagnostics != want {
			t.Fatalf("zero default override: %+v want %+v", config.diagnostics, want)
		}
	}
}
