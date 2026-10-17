// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/preflight_reports_test.go; SHA-256 68470a2da1ac14c461d920ee55d0e2195a081ea51b14721f500c8c347e6067a8.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

func TestBERPreflightReportsRetainDistinctTypedFields(t *testing.T) {
	wire := structureWire(t, "30060c01ff0c01ff")
	var reports ViolationLog
	options, commit := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports)})
	options = TrackBERForm(ChildDecodeOptions(options, "message"))
	if err := ValidateBERElement(wire, options...); err != nil {
		t.Fatal(err)
	}
	for index, field := range []string{"first", "second"} {
		child := wire[2+3*index : 5+3*index]
		if _, _, err := DecodeString(child, tag.TagUTF8String, ChildDecodeOptions(options, field)...); err != nil {
			t.Fatal(err)
		}
	}
	commit(true)
	got := reports.Snapshot()
	if len(got) != 2 || got[0].Path != "message.first" || got[1].Path != "message.second" {
		t.Fatalf("distinct violations collapsed or duplicated: %+v", got)
	}
}

func TestBERPreflightReportsDiscardFailedDecode(t *testing.T) {
	var reports ViolationLog
	options, commit := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports)})
	if err := ValidateBERElement(structureWire(t, "30050c01ff0200"), options...); err == nil {
		t.Fatal("invalid sibling accepted")
	}
	commit(false)
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed generated decode published reports")
	}
}

func TestBERPreflightUTF8LinearCost(t *testing.T) {
	var baselineTime int64
	for _, fragments := range []int{256, 1024, 4096, 16384} {
		// The final octet is invalid, so validation traverses and concatenates
		// the full string even under tolerance. This catches repeated copying
		// or rescanning of accumulated contents as fragment counts grow.
		contents := bytes.Repeat([]byte{4, 1, 'A'}, fragments)
		contents[len(contents)-1] = 0xff
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String, Constructed: true}, contents))
		operation := func() {
			var reports ViolationLog
			options, finish := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports)})
			options = TrackBERForm(options)
			if err := ValidateBERElement(wire, options...); err != nil {
				t.Fatal(err)
			}
			finish(true)
			if len(reports.Snapshot()) != 1 || !BERNeedsPreservation(options) {
				t.Fatal("preflight duplicated its report or lost the received-form marker")
			}
		}
		allocated, _ := allocationCost(t, 5, operation)
		// Repeated scans can be quadratic without allocating more memory.
		elapsed := minimumTime(t, operation)
		if allocated := int64(allocated); allocated > int64(8*len(wire)+8192) {
			t.Fatalf("%d fragments: allocated %d bytes for %d input bytes", fragments, allocated, len(wire))
		}
		if baselineTime == 0 {
			baselineTime = max(1, elapsed.Nanoseconds())
		}
		// Bound allocation-free rescanning as well as copying.
		if elapsed.Nanoseconds() > 16*baselineTime*int64(fragments/256) {
			t.Fatalf("%d fragments: %d ns exceeds linear bound", fragments, elapsed.Nanoseconds())
		}
		t.Logf("%d fragments: %d ns/op, %d bytes/op", fragments, elapsed.Nanoseconds(), int64(allocated))
	}
}
