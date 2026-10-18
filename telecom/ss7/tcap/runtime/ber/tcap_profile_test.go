// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile_test.go; SHA-256 a82f2fc4fbaf817ecc5673982ebc0b9b9c1bbea77c6593213bf963979b64d888.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestTCAPProfile(t *testing.T) {
	for _, tc := range []struct {
		wire, rule string
		offset     int
	}{
		{"308100", "short-length", 0},
		{"3003058100", "short-length", 2},
		{"30820000", "minimum-length-octets", 0},
		{"2403040101", "primitive-octet-string", 0},
		{"2380030207800000", "primitive-bit-string", 0},
	} {
		data, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		options := TrackTCAPForm(nil)
		err = ValidateBERElement(data, options...)
		var failure *ValidationError
		if !errors.As(err, &failure) || failure.Rule != (RuleRef{Document: "ITU-T Q.773", Edition: "06/1997", Clause: "4.1.1"}) || failure.Offset == nil || *failure.Offset != tc.offset {
			t.Fatalf("%s: missing located profile failure: %+v %v", tc.wire, failure, err)
		}
		var reports ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
		options = TrackTCAPForm(options)
		for range 2 {
			if err = ValidateBERElement(data, options...); err != nil {
				t.Fatalf("%s: %v", tc.wire, err)
			}
		}
		finish(true)
		if rows := reports.Snapshot(); len(rows) != 1 {
			t.Fatalf("%s: duplicate profile reports: %+v", tc.wire, rows)
		}
		if err = ValidateBERElement(data); err != nil {
			t.Fatalf("generic BER profile leaked: %v", err)
		}
	}
	for _, wire := range []string{"308005000000", "30052403040101"} {
		data, _ := hex.DecodeString(wire)
		err := ValidateBERElement(data, TrackTCAPForm(nil)...)
		if wire == "308005000000" && err != nil {
			t.Fatal("legal indefinite container rejected", err)
		}
	}
	canonical := append([]byte{0x04, 0x81, 0x80}, bytes.Repeat([]byte{0}, 128)...)
	if err := ValidateBERElement(canonical, TrackTCAPForm(nil)...); err != nil {
		t.Fatal("minimal long length rejected", err)
	}
	nonminimal := append([]byte{0x04, 0x82, 0, 0x80}, bytes.Repeat([]byte{0}, 128)...)
	if err := ValidateBERElement(nonminimal, TrackTCAPForm(nil)...); err == nil {
		t.Fatal("leading zero long length accepted")
	}
}

func FuzzBERProfile(f *testing.F) {
	for _, wire := range [][]byte{{0x30, 0x80, 0x05, 0, 0, 0}, {0x30, 0x81, 0}, {0x24, 3, 4, 1, 1}} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var reports ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
		err := ValidateBERElement(data, TrackTCAPForm(options)...)
		finish(err == nil)
		if err != nil && len(reports.Snapshot()) != 0 {
			t.Fatal("failed profile validation published reports")
		}
		if err == nil && ValidateBERElement(data) != nil {
			t.Fatal("tolerance accepted malformed BER")
		}
	})
}
