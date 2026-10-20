// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque_alias_test.go; SHA-256 820a1730fb1c7a31d606dec074847c03f1c876bc79c533cf43ce9acd8cebf5c2.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestOpaqueAliasedEncodePositions(t *testing.T) {
	wire := []byte{12, 1, 255}
	var reports ViolationLog
	options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
	for i, path := range []string{"left", "right", "left"} {
		value := wire
		if i == 2 {
			value = bytes.Clone(wire)
		}
		opts := EncodeSource(ChildEncodeOptions(options, path), "Module.Value")
		if err := CheckBEROpaqueElement(value, opts...); err != nil {
			t.Fatal(err)
		}
	}
	finish(true)
	rows := reports.Snapshot()
	if len(rows) != 2 || rows[0].Path != "left" || rows[1].Path != "right" {
		t.Fatalf("aliased records=%+v", rows)
	}
}

func TestOpaqueAliasedEncodeBudget(t *testing.T) {
	for _, n := range []int{1, 32, 1024, 1025} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			wire := []byte{12, 1, 255}
			var reports ViolationLog
			options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
			var err error
			for i := range n {
				opts := ChildEncodeOptions(options, fmt.Sprintf("child[%d]", i))
				err = CheckBEROpaqueElement(wire, opts...)
				if err != nil {
					break
				}
			}
			finish(err == nil)
			if n > DefaultDiagnosticLimits().MaxRecords {
				if !errors.Is(err, ErrResourceLimit) || len(reports.Snapshot()) != 0 {
					t.Fatalf("over budget: %v %+v", err, reports.Snapshot())
				}
			} else if err != nil || len(reports.Snapshot()) != n {
				t.Fatalf("n=%d: %v records=%d", n, err, len(reports.Snapshot()))
			}
		})
	}
}
