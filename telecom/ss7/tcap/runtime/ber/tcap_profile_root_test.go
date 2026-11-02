// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile_root_test.go; SHA-256 5c4a9237ced838e8eb849be58684668b21fda2339112621541c0e3d4e7e660bd.
package ber

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Q.773 (06/1997) Annex A and §4.1.1: only admitted TCMessage
// alternatives own the encoding profile, independently of the tag class.
func TestTCAPProfileUnadmittedRootClasses(t *testing.T) {
	for _, wire := range []string{"638103480101", "308103480101", "a28103480101", "e28103480101"} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range [][]string{nil, {"TCMessage", "TCAPMessages", "TCMessage"}} {
			if err = ValidateBERElement(data, TrackTCAPForm(nil, root...)...); err != nil {
				t.Errorf("%s: %v", wire, err)
			}
		}
	}
	data, _ := hex.DecodeString("428103480101")
	err := ValidateBERElement(data, TrackTCAPForm(nil)...)
	var profile *ValidationError
	if !errors.As(err, &profile) || profile.Constraint != "Q.773 §4.1.1: short-length" {
		t.Fatalf("primitive Begin loses its profile: %v", err)
	}
}

// The failed message's outer pass cannot validate a leading ID when the
// failure is at its header. Existing options must not suppress this pass.
func TestTCAPTransactionIDStandaloneProfile(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want error
	}{
		{"480101", nil}, {"490102", nil}, {"48810101", ErrInvalidValue},
		{"4982000102", ErrInvalidValue}, {"6803040101", ErrInvalidValue},
		{"6903040102", ErrInvalidValue}, {"480201", ErrTruncated},
		{"040101", ErrUnexpectedElement}, {"", ErrTruncated},
		{"04", ErrTruncated}, {"040201", ErrTruncated},
		// Well-formed BER that breaks only the ID profile: not an ID.
		{"04810101", ErrUnexpectedElement}, {"2403040101", ErrUnexpectedElement},
		{"88810101", ErrUnexpectedElement}, {"4a82000101", ErrUnexpectedElement},
	} {
		data, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]DecodeOption{nil, TrackTCAPForm(nil)} {
			checkAssociatedCardinalityError(t, ValidateTCAPTransactionID(data, options...), tc.want)
		}
	}
	var log ViolationLog
	options, discard := StageDecodeReports([]DecodeOption{WithTolerance(&log)})
	data, _ := hex.DecodeString("48810101")
	if err := ValidateTCAPTransactionID(data, options...); err != nil {
		t.Fatal(err)
	}
	discard(false)
	if len(log.Snapshot()) != 0 {
		t.Fatal("diagnostic prefix scan leaked reports")
	}
}
