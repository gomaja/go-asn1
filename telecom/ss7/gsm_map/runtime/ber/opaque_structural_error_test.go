// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque_structural_error_test.go; SHA-256 685042a8f6c8e41b07410198f22bf4f9dca833b549d85b1bd76acf7d5e137b8b.
package ber

import (
	"errors"
	"strings"
	"testing"
)

func TestFreshOpaqueKeepsStructuralFailure(t *testing.T) {
	for _, tc := range []struct{ wire, want string }{
		{"300a308002010500000c01ff", "indefinite length not allowed in DER"},
		{"30060101010c01ff", "BOOLEAN"},
	} {
		data := structureWire(t, tc.wire)
		err := CheckBEROpaqueElement(data, WithoutBERReplay())
		var validation *ValidationError
		if err == nil || !strings.Contains(err.Error(), tc.want) || errors.As(err, &validation) {
			t.Fatalf("structural error replaced: %T %v", err, err)
		}
	}
}

func TestStrictOpaqueRefusalPath(t *testing.T) {
	const source = "Module.Record.argument"
	data := structureWire(t, "0c01ff")
	var log ViolationLog
	if err := ValidateBERElement(data, LocateDecodedElement(data, source, ChildDecodeOptions([]DecodeOption{WithTolerance(&log)}, "argument"))...); err != nil {
		t.Fatal(err)
	}
	d := log.Snapshot()
	err := CheckBEROpaqueElement(data, EncodeSource(ChildEncodeOptions(nil, "argument"), source)...)
	ve, bare := err.(*ValidationError)
	if len(d) != 1 || !bare {
		t.Fatalf("records=%+v err=%T %v", d, err, err)
	}
	if ve.Path != d[0].Path || ve.Source != d[0].Source || ve.Rule != d[0].Rule || ve.ObservedValue != d[0].ObservedValue {
		t.Fatalf("strict=%+v decoded=%+v", ve, d[0])
	}
}
