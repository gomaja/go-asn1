// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_encode_reports_test.go; SHA-256 f1bff7ec0d2cba386f4b1d758600c23370a44b65b972887136401cd85990ca5f.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// Q.773 (06/1997) §4.1.1: encode findings describe abstract positions,
// whereas strict failures and decode findings retain their wire coordinates.
func TestTCAPEncodeProfileAbstractPositions(t *testing.T) {
	// DialoguePortion and its EXTERNAL child have the same diagnostic path.
	// Moving the second header by lengthening the first must not create a
	// second report for the same abstract position on a repeated staged check.
	for _, wires := range [][]string{
		{"02810101", "02810101"},
		{"6b8200082882000481020000", "6b830000082882000481020000"},
	} {
		var log ViolationLog
		options, commit := StageEncodeReports([]EncodeOption{WithTolerance(&log)})
		kind := "TCInvokeIdSet"
		want := 1
		if len(wires[0]) > 8 {
			kind = "DialoguePortion"
			want = 2
		}
		_, finish := StageTCAPEncode(options, kind)
		for _, text := range wires {
			wire, _ := hex.DecodeString(text)
			if err := finish(wire, nil); err != nil {
				t.Fatal(err)
			}
		}
		commit(true)
		rows := log.Snapshot()
		if len(rows) != want {
			t.Fatalf("%s: got %d reports, want %d: %+v", kind, len(rows), want, rows)
		}
		if want == 2 && (rows[0].Path != "DialoguePortion" || rows[1].Path != rows[0].Path) {
			t.Fatalf("same-path control: %+v", rows)
		}
		for _, v := range rows {
			if v.Offset != nil || v.OctetOffset != nil || v.ChildIndexes != nil {
				t.Fatalf("encode coordinates: %+v", v)
			}
		}
		wire, _ := hex.DecodeString(wires[0])
		var decoded ViolationLog
		if err := ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&decoded)}, kind)...); err != nil {
			t.Fatal(err)
		}
		before := decoded.Snapshot()
		if len(before) != want {
			t.Fatalf("decode rows: %+v", before)
		}
		for i, v := range before {
			if v.Offset == nil {
				t.Fatalf("decode coordinate lost: %+v", v)
			}
			v.Offset = nil
			v.ChildIndexes = nil
			if !reflect.DeepEqual(v, rows[i]) {
				t.Fatalf("encode metadata changed: got %+v want %+v", rows[i], v)
			}
		}
		_, strict := StageTCAPEncode(nil, kind)
		var failure *ValidationError
		if err := strict(wire, nil); !errors.As(err, &failure) || failure.Offset == nil || *failure.Offset != 0 {
			t.Fatalf("strict failure: %+v %v", failure, err)
		}
		_, failed := StageTCAPEncode(options, kind)
		sentinel := errors.New("prior")
		if !errors.Is(failed(bytes.Clone(wire), sentinel), sentinel) {
			t.Fatal("prior failure lost")
		}
	}
}
