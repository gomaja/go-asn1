// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/triage_encode_policy_test.go; SHA-256 204e333691f8fa9b32e797335ee8e2fbd80aeb8f4ecf7268d100d933576825d8.
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
	if err := CheckBEROpaqueReplay(WithoutBERReplay(), WithTolerance(&log)); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("tolerance admitted opaque replay: %v", err)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatal("opaque refusal published subtype reports")
	}
}
