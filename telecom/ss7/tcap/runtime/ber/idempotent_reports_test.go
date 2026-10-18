// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/idempotent_reports_test.go; SHA-256 323c1dda51c46500a216d72608003ccc8f57adf97c0c9395f61f5707a4b794c0.
package ber

import (
	"bytes"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"reflect"
	"sync"
	"testing"
)

func TestViolationLogIdempotentStaging(t *testing.T) {
	var reports ViolationLog
	for range 2 {
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
		for range 2 {
			if err := CheckDecodedValue(options, "text", "(0)", "1"); err != nil {
				t.Fatal(err)
			}
		}
		child, childFinish := StageDecodeReports(options)
		if err := CheckDecodedValue(child, "text", "(0)", "1"); err != nil {
			t.Fatal(err)
		}
		childFinish(true)
		finish(true)
	}
	if got := reports.Snapshot(); len(got) != 2 {
		t.Fatalf("want one record per successful decode, got %+v", got)
	}
}

func TestViolationLogIdempotentEncodeStaging(t *testing.T) {
	var reports ViolationLog
	for index, success := range []bool{false, true, true} {
		options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
		for range 2 {
			if err := CheckEncodedValue(options, "text", "(0)", "1"); err != nil {
				t.Fatal(err)
			}
		}
		child, childFinish := StageEncodeReports(options)
		if err := CheckEncodedValue(child, "text", "(0)", "1"); err != nil {
			t.Fatal(err)
		}
		childFinish(true)
		finish(success)
		if got := reports.Snapshot(); len(got) != index {
			t.Fatalf("encode success %t: want %d records, got %+v", success, index, got)
		}
	}
}

func TestBERUTF8ReportsDistinctOctets(t *testing.T) {
	for _, encoded := range []string{"0c03ff41fe", "2c090401ff0401410401fe", "2c800401ff2480040241fe00000000"} {
		t.Run(encoded, func(t *testing.T) {
			wire := structureWire(t, encoded)
			var reports ViolationLog
			options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
			options = TrackBERForm(ChildDecodeOptions(options, "message"))
			if err := ValidateBERElement(wire, options...); err != nil {
				t.Fatal(err)
			}
			text, _, err := DecodeString(wire, tag.TagUTF8String, ChildDecodeOptions(options, "text")...)
			if err != nil || !bytes.Equal([]byte(text), []byte{255, 'A', 254}) {
				t.Fatalf("typed octets %x, error %v", text, err)
			}
			finish(true)
			got := reports.Snapshot()
			if len(got) != 2 {
				t.Fatalf("different malformed octets require two reports, got %+v", got)
			}
			for index, offset := range []int{0, 2} {
				if got[index].OctetOffset == nil || *got[index].OctetOffset != offset || got[index].Path != "message.text" {
					t.Fatalf("wrong offset or path: %+v", got[index])
				}
			}
		})
	}
}

func TestViolationLogDistinctKeysAndReset(t *testing.T) {
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	for _, value := range []struct{ path, constraint, observed string }{
		{"first", "(0)", "1"}, {"first", "(0)", "1"},
		{"second", "(0)", "1"}, {"first", "(2)", "1"}, {"first", "(0)", "3"},
	} {
		if err := CheckDecodedValue(options, value.path, value.constraint, value.observed); err != nil {
			t.Fatal(err)
		}
	}
	for _, length := range []int{2, 2, 3} {
		if err := CheckDecodedLength(options, "first", "SIZE (1)", length); err != nil {
			t.Fatal(err)
		}
	}
	finish(true)
	finish(true) // Publishing a successful stage twice is idempotent as well.
	if got := reports.Snapshot(); len(got) != 6 {
		t.Fatalf("distinct paths, constraints or observations collapsed: %+v", got)
	}
	direct := []DecodeOption{WithTolerance(&reports)}
	if err := CheckDecodedValue(direct, "first", "(0)", "1"); err != nil {
		t.Fatal(err)
	}
	reports.Reset()
	if err := CheckDecodedValue(direct, "first", "(0)", "1"); err != nil {
		t.Fatal(err)
	}
	if got := reports.Snapshot(); len(got) != 1 {
		t.Fatalf("Reset left stale deduplication keys: %+v", got)
	}
}

func TestBERPreflightOpaqueDistinctStrings(t *testing.T) {
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	if err := ValidateBERElement(structureWire(t, "30060c01ff0c01ff"), options...); err != nil {
		t.Fatal(err)
	}
	finish(true)
	if got := reports.Snapshot(); len(got) != 2 {
		t.Fatalf("same path and local offset in different opaque strings collapsed: %+v", got)
	}
}

func TestViolationLogResetWireReports(t *testing.T) {
	var reports ViolationLog
	wire := structureWire(t, "0c01ff")
	options := []DecodeOption{WithTolerance(&reports)}
	if _, _, err := DecodeString(wire, tag.TagUTF8String, options...); err != nil {
		t.Fatal(err)
	}
	reports.Reset()
	if _, _, err := DecodeString(wire, tag.TagUTF8String, ChildDecodeOptions(options, "text")...); err != nil {
		t.Fatal(err)
	}
	if got := reports.Snapshot(); len(got) != 1 || got[0].Path != "text" {
		t.Fatalf("Reset retained stale wire indexes: %+v", got)
	}
}

func TestBERUTF8SeparateToleranceScopes(t *testing.T) {
	var reports ViolationLog
	wire := structureWire(t, "0c01ff")
	for range 2 {
		options := []DecodeOption{WithTolerance(&reports)}
		for range 2 {
			if _, _, err := DecodeString(wire, tag.TagUTF8String, options...); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := reports.Snapshot(); len(got) != 4 {
		t.Fatalf("independent decode scopes collapsed or duplicated: %+v", got)
	}
}

func TestBERUTF8NestedStagingAndRollback(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(fmt.Sprint(success), func(t *testing.T) {
			wire := structureWire(t, "30060c01ff0c01ff")
			var reports ViolationLog
			parent, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
			parent = TrackBERForm(ChildDecodeOptions(parent, "message"))
			if err := ValidateBERElement(wire, parent...); err != nil {
				t.Fatal(err)
			}
			for index, field := range []string{"first", "second"} {
				child, childFinish := StageDecodeReports(ChildDecodeOptions(parent, field))
				if _, _, err := DecodeString(wire[2+3*index:5+3*index], tag.TagUTF8String, child...); err != nil {
					t.Fatal(err)
				}
				childFinish(true)
			}
			if len(reports.Snapshot()) != 0 {
				t.Fatal("nested call published before parent success")
			}
			finish(success)
			got := reports.Snapshot()
			if !success {
				if len(got) != 0 {
					t.Fatal("failed parent published nested reports")
				}
				return
			}
			if len(got) != 2 || got[0].Path != "message.first" || got[1].Path != "message.second" {
				t.Fatalf("nested stages duplicated or lost field reports: %+v", got)
			}
		})
	}
}

func TestBERUTF8ReportOrderAndSnapshot(t *testing.T) {
	for _, typedFirst := range []bool{false, true} {
		wire := structureWire(t, "0c01ff")
		var reports ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
		typed := ChildDecodeOptions(options, "text")
		if typedFirst {
			if _, _, err := DecodeString(wire, tag.TagUTF8String, typed...); err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			if err := ValidateBERElement(wire, options...); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := DecodeString(wire, tag.TagUTF8String, typed...); err != nil {
			t.Fatal(err)
		}
		config, err := decodeOptions(options)
		if err != nil {
			t.Fatal(err)
		}
		got := config.violations.Snapshot()
		if len(got) != 1 || got[0].Path != "text" || got[0].OctetOffset == nil || *got[0].OctetOffset != 0 {
			t.Fatalf("report order %t: %+v", typedFirst, got)
		}
		*got[0].OctetOffset = 99
		if *config.violations.Snapshot()[0].OctetOffset != 0 {
			t.Fatal("snapshot exposes mutable octet offsets")
		}
		// A second schema field referring to these octets is a distinct typed
		// report; provisional-path reconciliation must not merge typed paths.
		if _, _, err := DecodeString(wire, tag.TagUTF8String, ChildDecodeOptions(options, "other")...); err != nil {
			t.Fatal(err)
		}
		finish(true)
		if got := reports.Snapshot(); len(got) != 2 || got[1].Path != "other" {
			t.Fatalf("different typed paths collapsed: %+v", got)
		}
	}
}

func TestViolationLogConcurrentIdempotency(t *testing.T) {
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			for range 100 {
				if err := CheckDecodedValue(options, "text", "(0)", "1"); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
	finish(true)
	if len(reports.Snapshot()) != 1 {
		t.Fatal("concurrent reports were not idempotent")
	}
}

func TestBERUTF8ReportOffsets(t *testing.T) {
	// Preserve correctly encoded U+FFFD, then locate three invalid octets after
	// valid multibyte scalars. Offsets count content octets, not characters.
	wire := structureWire(t, "0c0befbfbde282acff41fefe41")
	var reports ViolationLog
	if _, _, err := DecodeString(wire, tag.TagUTF8String, WithTolerance(&reports)); err != nil {
		t.Fatal(err)
	}
	var offsets []int
	for _, record := range reports.Snapshot() {
		if record.OctetOffset == nil {
			t.Fatal("missing octet offset")
		}
		offsets = append(offsets, *record.OctetOffset)
	}
	if !reflect.DeepEqual(offsets, []int{6, 8, 9}) {
		t.Fatalf("offsets %v", offsets)
	}
}
