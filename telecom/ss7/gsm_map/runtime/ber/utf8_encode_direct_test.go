// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_encode_direct_test.go; SHA-256 9b00b0331336f8fdd41e754c6fc362b2ab5393c487e897d0f984e24981920160.
package ber

import (
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestTypedUTF8DirectCheck(t *testing.T) {
	const source = "Module.Record.text"
	for _, value := range []string{"a", "é", "\xff", "\xff\xff", "a\xe2\x82"} {
		wire, err := EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, []byte(value))
		if err != nil {
			t.Fatal(err)
		}
		var decoded, encoded ViolationLog
		decode := LocateDecodedElement(wire, source, ChildDecodeOptions([]DecodeOption{WithTolerance(&decoded)}, "text"))
		if err := ValidateBERElement(wire, decode...); err != nil {
			t.Fatal(err)
		}
		options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&encoded)})
		err = checkEncodedUTF8String(value, EncodeRule(options, source, RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}), "text")
		finish(err == nil)
		if err != nil {
			t.Fatal(err)
		}
		want, got := decoded.Snapshot(), encoded.Snapshot()
		for i := range want {
			want[i].Offset = nil
			want[i].OctetOffset = nil
			want[i].ChildIndexes = nil
		}
		if len(got) != len(want) {
			t.Fatalf("%q: %d records, want %d", value, len(got), len(want))
		}
		for i := range got {
			if got[i].Path != want[i].Path || got[i].Source != want[i].Source || got[i].Rule != want[i].Rule || got[i].Constraint != want[i].Constraint || got[i].ObservedValue != want[i].ObservedValue || got[i].Offset != nil || got[i].OctetOffset != nil || len(got[i].ChildIndexes) != 0 {
				t.Fatalf("%q: record %+v, want %+v", value, got[i], want[i])
			}
		}
		if len(got) > 0 {
			var element *ElementError
			var validation *ValidationError
			err = checkEncodedUTF8String(value, EncodeSource(nil, source), "text")
			if errors.As(err, &element) || !errors.As(err, &validation) || !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error=%v", err)
			}
		}
	}
	var reports ViolationLog
	options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
	defer finish(false)
	if n := testing.AllocsPerRun(100, func() {
		if err := checkEncodedUTF8String("valid", options, "element"); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("valid text diagnostic allocations=%.0f", n)
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("valid text reported a violation")
	}
}

func TestTypedUTF8EncodeDiagnosticsGrowLinearly(t *testing.T) {
	rule := RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}
	for _, size := range []int{64, 128, 256, 512, 1024} {
		value := strings.Repeat("\xff", size)
		allocated := testing.AllocsPerRun(2, func() {
			var reports ViolationLog
			options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
			err := CheckEncodedValue(EncodeRule(options, "Module.Record.text", rule), "text", "UTF8String", value)
			finish(err == nil)
			if err != nil || len(reports.Snapshot()) != size {
				t.Fatalf("size=%d error=%v records=%d", size, err, len(reports.Snapshot()))
			}
		})
		if allocated > float64(32*size+256) {
			t.Fatalf("size=%d allocations=%.0f exceed linear bound", size, allocated)
		}
	}
	var reports ViolationLog
	options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
	err := CheckEncodedValue(EncodeRule(options, "Module.Record.text", rule), "text", "UTF8String", strings.Repeat("\xff", 1025))
	finish(err == nil)
	if !errors.Is(err, ErrResourceLimit) || len(reports.Snapshot()) != 0 {
		t.Fatalf("limit error=%v records=%d", err, len(reports.Snapshot()))
	}
}
