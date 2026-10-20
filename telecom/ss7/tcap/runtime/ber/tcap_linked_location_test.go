// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_linked_location_test.go; SHA-256 f278c13c344f8f2c4a5ed5934a33721bf58967bdd81bb1f16da039f259026aec.
package ber

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// X.880 (07/1994) Annex A: both linkedId alternatives belong to the
// Invoke, so a Q.773 (06/1997) §4.1.1 finding must identify that field.
func TestTCAPLinkedIDProfileLocation(t *testing.T) {
	for _, row := range []struct{ name, wire string }{
		{"present", "62114801016c0ca10a02010180810102020102"},
		{"absent", "62104801016c0ba109020101818100020101"},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			path := "begin.components.element[0].basicROS.invoke.linkedId." + row.name
			var log ViolationLog
			if err := ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "TCMessage")...); err != nil {
				t.Fatal(err)
			}
			rows := log.Snapshot()
			if len(rows) != 1 {
				t.Fatalf("reports=%+v", rows)
			}
			check := func(v Violation) {
				t.Helper()
				if v.Path != path || v.Offset == nil || *v.Offset != 12 || !reflect.DeepEqual(v.ChildIndexes, []int{1, 0, 1}) || v.Constraint != "Q.773 §4.1.1: short-length" {
					t.Fatalf("location=%+v, want %s at 12 [1 0 1]", v, path)
				}
			}
			check(rows[0])
			err = ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...)
			var failure *ValidationError
			if !errors.As(err, &failure) {
				t.Fatalf("strict error=%v", err)
			}
			check(failure.Violation)
		})
	}
}
