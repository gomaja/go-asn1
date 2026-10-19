// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/preflight_reports_test.go; SHA-256 4737fab5d3649b0dfe5167a7d687afb013381e00b17bf812718a17ada3196a0c.
package ber

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// Match generated UnmarshalBER: stage reports, track received forms, preflight
// the whole value, then decode typed fields with their schema paths. X.690
// (02/2021) §§8.23.3, 8.23.10 govern the invalid concatenated text.
func TestBERPreflightTypedUTF8Reports(t *testing.T) {
	for _, encoded := range []string{"0c01ff", "0c02c080", "0c03eda080", "0c02e282", "2c070401e2040282ff", "2c800401ff0000"} {
		wantReports := map[string]int{"0c01ff": 1, "0c02c080": 2, "0c03eda080": 3, "0c02e282": 2, "2c070401e2040282ff": 3, "2c800401ff0000": 1}[encoded]
		for _, implicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/implicit%t", encoded, implicit), func(t *testing.T) {
				wire := structureWire(t, encoded)
				var reports ViolationLog
				for decode := range 2 {
					options, commit := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
					options = TrackBERForm(ChildDecodeOptions(options, "message"))
					for range 2 {
						if err := ValidateBERElement(wire, options...); err != nil {
							t.Fatal(err)
						}
					}
					var text string
					var err error
					childOptions := ChildDecodeOptions(options, "text")
					if implicit {
						outer, _, contents, tlvErr := DecodeTLV(wire, options...)
						if tlvErr != nil {
							t.Fatal(tlvErr)
						}
						text, err = DecodeImplicitStringValue(tag.TagUTF8String, outer.Constructed, contents, childOptions...)
					} else {
						text, _, err = DecodeString(wire, tag.TagUTF8String, childOptions...)
					}
					if err != nil {
						t.Fatal(err)
					}
					if !BERNeedsPreservation(options) {
						t.Fatal("invalid received text lost its preservation marker")
					}
					// The generated snapshot contains the typed octets; replay
					// retains the original length and fragment spelling as well.
					snapshot := mustEncode(t)(EncodeUTF8String(text))
					rebuilt := mustEncode(t)(EncodeUTF8String(text))
					if replay := PreserveEncodedBER(rebuilt, wire, snapshot, nil); !bytes.Equal(replay, wire) {
						t.Fatalf("replay %x want %x", replay, wire)
					}
					changed := mustEncode(t)(EncodeUTF8String(text + "A"))
					if replay := PreserveEncodedBER(changed, wire, snapshot, nil); !bytes.Equal(replay, changed) {
						t.Fatal("changed typed text replayed the original")
					}
					commit(true)
					got := reports.Snapshot()
					if len(got) != (decode+1)*wantReports {
						t.Fatalf("one report per malformed octet per decode required: %+v", got)
					}
					for _, record := range got {
						if record.Path != "message.text" || !strings.Contains(record.Constraint, "UTF8String") {
							t.Fatalf("wrong typed report: %+v", record)
						}
					}
				}
			})
		}
	}
}

func TestBERPreflightReportsRetainDistinctTypedFields(t *testing.T) {
	wire := structureWire(t, "30060c01ff0c01ff")
	var reports ViolationLog
	options, commit := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
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
	options, commit := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
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
			options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
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
