// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tolerance_policy_test.go; SHA-256 95dd2dc63b1e426a983fa28c8561b179cf7aacc8a350112afdf970341a71519b.
package ber

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestToleranceRuleIdentity(t *testing.T) {
	rule := "Q.773 §4.2.2.2: component-id-one-octet"
	err := CheckDecodedValue(nil, "invokeId", rule, "128")
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("missing typed validation error: %v", err)
	}
	record := reflect.ValueOf(validation.Violation)
	field := record.FieldByName("Rule")
	if !field.IsValid() {
		t.Fatal("validation lacks stable rule identity")
	}
	if field.FieldByName("Document").String() != "ITU-T Q.773" || field.FieldByName("Edition").String() != "06/1997" || field.FieldByName("Clause").String() != "4.2.2.2" {
		t.Fatalf("wrong rule: %+v", field.Interface())
	}
	var reports ViolationLog
	opts, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	for range 2 {
		if err := CheckDecodedValue(opts, "invokeId", rule, "128"); err != nil {
			t.Fatal(err)
		}
	}
	finish(true)
	if len(reports.Snapshot()) != 1 {
		t.Fatal("one failure reported more than once")
	}
}

func TestToleranceOptionAndSnapshot(t *testing.T) {
	if err := ValidateDecodeOptions(WithTolerance(nil)); err == nil {
		t.Fatal("nil decode sink accepted")
	}
	if err := ValidateEncodeOptions(WithTolerance(nil)); err == nil {
		t.Fatal("nil encode sink accepted")
	}
	var log ViolationLog
	opts, finish := StageDecodeReports([]DecodeOption{WithTolerance(&log)})
	opts = LocateDecodedElement([]byte{2, 1, 127}, "TCInvokeIdSet", opts)
	if err := CheckDecodedValue(opts, "present", "Q.773 §4.2.2.2: component-id-one-octet", "128"); err != nil {
		t.Fatal(err)
	}
	finish(true)
	first := log.Snapshot()
	if first[0].Offset == nil || *first[0].Offset != 0 {
		t.Fatalf("missing wire offset: %+v", first[0])
	}
	*first[0].Offset = 100
	if *log.Snapshot()[0].Offset != 0 {
		t.Fatal("snapshot aliases offset")
	}
	fresh := CheckEncodedValue(nil, "present", "Q.773 §4.2.2.2: component-id-one-octet", "128")
	var validation *ValidationError
	if !errors.As(fresh, &validation) || validation.Offset != nil {
		t.Fatalf("fresh value has wire offset: %v", fresh)
	}
	options := TrackBERForm([]DecodeOption{WithoutReplayCapture()})
	MarkBERNonCanonical(options)
	if BERNeedsPreservation(options) || CaptureGeneratedBERReplay([]byte{5, 0}, options) != nil {
		t.Fatal("capture retained despite opt-out")
	}
}

func TestStrictAndTolerantViolationIdentity(t *testing.T) {
	err := CheckDecodedValue(nil, "invokeId", "Q.773 §4.2.2.2: component-id-one-octet", "128")
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatal(err)
	}
	var log ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&log)})
	if err = CheckDecodedValue(options, "invokeId", "Q.773 §4.2.2.2: component-id-one-octet", "128"); err != nil {
		t.Fatal(err)
	}
	finish(true)
	if !reflect.DeepEqual(validation.Violation, log.Snapshot()[0]) {
		t.Fatalf("strict/tolerant records differ: %+v %+v", validation.Violation, log.Snapshot()[0])
	}
}

func TestStrictObservationsAreBounded(t *testing.T) {
	observation := strings.Repeat("x", 4<<20)
	for _, encode := range []bool{false, true} {
		var err error
		var log ViolationLog
		if encode {
			err = CheckEncodedValue(nil, "present", "Q.773 §4.2.2.2: component-id-one-octet", observation)
			if failure := CheckEncodedValue([]EncodeOption{WithTolerance(&log)}, "present", "Q.773 §4.2.2.2: component-id-one-octet", observation); failure != nil {
				t.Fatal(failure)
			}
		} else {
			err = CheckDecodedValue(nil, "present", "Q.773 §4.2.2.2: component-id-one-octet", observation)
			if failure := CheckDecodedValue([]DecodeOption{WithTolerance(&log)}, "present", "Q.773 §4.2.2.2: component-id-one-octet", observation); failure != nil {
				t.Fatal(failure)
			}
		}
		var validation *ValidationError
		if !errors.As(err, &validation) || len(validation.ObservedValue) != MaxObservedValueBytes || validation.ObservedValueLength != len(observation) {
			t.Fatalf("encode%v: unbounded strict observation", encode)
		}
		if !reflect.DeepEqual(validation.Violation, log.Snapshot()[0]) {
			t.Fatalf("encode%v: strict/tolerant records differ", encode)
		}
	}
}
