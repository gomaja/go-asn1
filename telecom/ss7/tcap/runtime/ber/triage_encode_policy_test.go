// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/triage_encode_policy_test.go; SHA-256 0170c2d17a81231809b397a980538080fcbe9dec4219c446afb669094e0c7c37.
package ber

import (
	"errors"
	"testing"
)

func TestBERReplayPolicyRefusesOpaqueValues(t *testing.T) {
	for _, options := range [][]EncodeOption{
		{WithoutBERReplay()},
		ChildEncodeOptions([]EncodeOption{WithoutBERReplay()}, "open"),
		ChildEncodeOptions([]EncodeOption{WithoutBERReplay()}, "extensions"),
	} {
		if err := CheckBEROpaqueReplay(options...); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("opaque replay error=%v", err)
		}
	}
	if err := CheckBEROpaqueReplay(); err != nil {
		t.Fatalf("default opaque replay=%v", err)
	}
	if err := CheckBEROpaqueReplay(nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("malformed option=%v", err)
	}
	var log ViolationLog
	if err := CheckBEROpaqueReplay(WithoutBERReplay(), WithConstraintTolerance(&log)); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("tolerance admitted opaque replay: %v", err)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatal("opaque refusal published subtype reports")
	}
}
