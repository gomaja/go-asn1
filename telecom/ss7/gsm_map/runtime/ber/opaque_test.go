// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque_test.go; SHA-256 26e5e6a346f7d84d30b6b8e5902706308ca26cb4efc6acde16e035b5102a8dff.
package ber

import (
	"bytes"
	"errors"
	"testing"
)

func TestFreshOpaqueElement(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wire      []byte
		canonical bool
	}{
		{"NULL", []byte{5, 0}, true},
		{"unknown implicit", []byte{0x9e, 1, 0xff}, true},
		{"nonminimal length", []byte{5, 0x81, 0}, false},
		{"indefinite", []byte{0x30, 0x80, 5, 0, 0, 0}, false},
		{"nonminimal integer", []byte{2, 2, 0, 1}, false},
		{"two elements", []byte{5, 0, 5, 0}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.wire)
			for _, tolerant := range []bool{false, true} {
				options := []EncodeOption{WithoutBERReplay()}
				var reports ViolationLog
				if tolerant {
					options = append(options, WithTolerance(&reports))
				}
				err := CheckBEROpaqueElement(tc.wire, options...)
				if (err == nil) != tc.canonical {
					t.Fatalf("canonical=%t: %v", tc.canonical, err)
				}
				if err != nil && !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("missing error identity: %v", err)
				}
				if !bytes.Equal(original, tc.wire) || len(reports.Snapshot()) != 0 {
					t.Fatal("opaque check changed input or reports")
				}
			}
		})
	}
	if err := CheckBEROpaqueElement([]byte{5, 0}, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid option: %v", err)
	}
}
