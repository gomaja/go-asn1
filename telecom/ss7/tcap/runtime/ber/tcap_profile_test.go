// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile_test.go; SHA-256 dd51df369a8fb5e59313948e114542a0b3e14f604ce0e3813e1a1842e3934f75.
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

// Q.773 (06/1997) §4.1.1 covers TCAP's abstract syntaxes. X.690
// (02/2021) §8.15 leaves an open type's complete TLV to its own syntax.
func TestTCAPProfileOpenTypeBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		refuse     bool
	}{
		{"invoke-control", "62154804000000016c0da10b0201010201023003040100", false},
		{"invoke-argument-header", "62164804000000016c0ea10c020101020102308103040100", false},
		{"invoke-argument-child", "62164804000000016c0ea10c020101020102300404810100", false},
		{"invoke-argument-constructed-string", "62184804000000016c10a10e0201010201023006240404020000", false},
		{"return-result-value", "64184904000000016c10a20e0201013009020102308103040100", false},
		{"return-error-parameter", "64164904000000016c0ea30c020101020105308103040100", false},
		{"transaction-id", "6216488104000000016c0da10b0201010201023003040100", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateBERElement(data, TrackTCAPForm(nil, "TCMessage")...)
			var failure *ValidationError
			if errors.As(err, &failure) != tc.refuse || err != nil && !tc.refuse {
				t.Fatalf("profile outcome: %v, want refusal %t", err, tc.refuse)
			}
		})
	}
}

// Q.773 (06/1997) §4.1.1 profiles the opcode after either X.880
// (07/1994) Invoke.linkedId alternative, including absent [1].
func TestTCAPProfileAfterAbsentLinkedID(t *testing.T) {
	wire, err := hex.DecodeString("62184804000000016c10a10e0201018100028101023003040100")
	if err != nil {
		t.Fatal(err)
	}
	var log ViolationLog
	if err := ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "TCMessage")...); err != nil {
		t.Fatal(err)
	}
	rows := log.Snapshot()
	if len(rows) != 1 || rows[0].Rule.Clause != "4.1.1" || !bytes.Contains([]byte(rows[0].Constraint), []byte("short-length")) {
		t.Fatalf("opcode profile finding: %+v", rows)
	}
}

// X.690 (02/2021) §§8.18.10–8.18.11: the segments encode EXTERNAL's
// OCTET STRING or BIT STRING; only the segment data is TC-user content.
func TestTCAPProfileExternalSegmentHeaders(t *testing.T) {
	wrap := func(id byte, parts ...[]byte) []byte {
		body := bytes.Join(parts, nil)
		return append([]byte{id, byte(len(body))}, body...)
	}
	for _, tc := range []struct{ name, choice string }{
		{"octet-aligned", "a10404810100"},
		{"arbitrary", "a2050381020000"},
	} {
		for _, scope := range []string{"foreign dialogue", "user information"} {
			t.Run(tc.name+"/"+scope, func(t *testing.T) {
				choice, err := hex.DecodeString(tc.choice)
				if err != nil {
					t.Fatal(err)
				}
				wire := wrap(0x62, []byte{0x48, 1, 1}, wrap(0x6b, wrap(0x28, []byte{6, 2, 42, 3}, choice)))
				if scope == "user information" {
					external := wrap(0x28, []byte{6, 2, 42, 3}, choice)
					apdu := wrap(0x60, []byte{0xa1, 4, 6, 2, 42, 3}, wrap(0xbe, external))
					wire = wrap(0x62, []byte{0x48, 1, 1}, wrap(0x6b, wrap(0x28,
						[]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, wrap(0xa0, apdu))))
				}
				var log ViolationLog
				if err := ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "TCMessage")...); err != nil {
					t.Fatal(err)
				}
				rows := log.Snapshot()
				if len(rows) != 2 || !bytes.Contains([]byte(rows[1].Constraint), []byte("short-length")) {
					t.Fatalf("EXTERNAL choice and segment findings: %+v", rows)
				}
			})
		}
	}
}

// Q.773 (06/1997) §§3.2, 4.1.1, 4.2.3 includes its dialogue abstract
// syntaxes, while X.690 (02/2021) §§8.18.9–8.18.11 puts the EXTERNAL data
// value in the syntax identified by the EXTERNAL fields.
func TestTCAPProfileExternalBoundary(t *testing.T) {
	wrap := func(identifier byte, fields ...[]byte) []byte {
		body := bytes.Join(fields, nil)
		return append([]byte{identifier, byte(len(body))}, body...)
	}
	known := []byte{6, 7, 0, 17, 134, 5, 1, 1, 1}
	foreign := []byte{6, 2, 42, 3}
	longValue := []byte{0x30, 0x81, 3, 4, 1, 0}
	build := func(oid, choice []byte) []byte {
		return wrap(0x62, []byte{0x48, 1, 1}, wrap(0x6b, wrap(0x28, oid, choice)))
	}
	for _, tc := range []struct {
		name string
		wire []byte
		deny bool
	}{
		{"foreign-single-value", build(foreign, wrap(0xa0, longValue)), false},
		{"foreign-single-choice-header", build(foreign, []byte{0xa0, 0x81, 6, 0x30, 3, 4, 1, 0}), true},
		{"foreign-octet-data", build(foreign, wrap(0x81, longValue)), false},
		{"foreign-octet-header", build(foreign, []byte{0x81, 0x81, 6, 0x30, 0x81, 3, 4, 1, 0}), true},
		{"foreign-bit-data", build(foreign, wrap(0x82, append([]byte{0}, longValue...))), false},
		{"foreign-bit-header", build(foreign, []byte{0x82, 0x81, 7, 0, 0x30, 0x81, 3, 4, 1, 0}), true},
		{"known-single-value", build(known, wrap(0xa0, []byte{0x60, 0x81, 6, 0xa1, 4, 6, 2, 42, 3})), true},
		{"user-information-single-value", build(known, wrap(0xa0, wrap(0x60,
			[]byte{0xa1, 4, 6, 2, 42, 3}, wrap(0xbe, wrap(0x28, foreign, wrap(0xa0, longValue)))))), false},
		{"user-information-choice-header", build(known, wrap(0xa0, wrap(0x60,
			[]byte{0xa1, 4, 6, 2, 42, 3}, wrap(0xbe, wrap(0x28, foreign,
				[]byte{0xa0, 0x81, 6, 0x30, 3, 4, 1, 0}))))), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBERElement(tc.wire, TrackTCAPForm(nil, "TCMessage")...)
			var failure *ValidationError
			if errors.As(err, &failure) != tc.deny || err != nil && !tc.deny {
				t.Fatalf("profile outcome: %v, want refusal %t", err, tc.deny)
			}
		})
	}
}

func TestTCAPForeignContentStillConsumesLinearBERBudget(t *testing.T) {
	// Q.773 (06/1997) §4.1.1 does not profile the X.690 (02/2021)
	// §8.15 argument, but the generic BER work and element limits still apply.
	wrap := func(id byte, content []byte) []byte {
		out := append([]byte{id}, EncodeLength(len(content))...)
		return append(out, content...)
	}
	for _, count := range []int{64, 128, 256, 512} {
		argument := wrap(0x30, bytes.Repeat([]byte{5, 0}, count))
		invoke := wrap(0xa1, append([]byte{2, 1, 1, 2, 1, 2}, argument...))
		wire := wrap(0x62, append([]byte{0x48, 1, 1}, wrap(0x6c, invoke)...))
		options := TrackTCAPForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: len(wire), MaxElements: count + 8})}, "TCMessage")
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatalf("%d foreign elements within linear budget: %v", count, err)
		}
		options = TrackTCAPForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: len(wire) - 1})}, "TCMessage")
		if err := ValidateBERElement(wire, options...); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("%d foreign elements exceeded byte budget: %v", count, err)
		}
		options = TrackTCAPForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxElements: count})}, "TCMessage")
		if err := ValidateBERElement(wire, options...); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("%d foreign elements exceeded element budget: %v", count, err)
		}
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
