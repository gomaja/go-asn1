// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/phase1_profile_test.go; SHA-256 2c32479a7d25ec2777d211d6fe997a71c44ea7d4d2716097432bfdcf2e8c6025.
package ber

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestMAPRepresentationEncodeRecords(t *testing.T) {
	for _, edition := range []struct {
		name   string
		track  func([]DecodeOption) []DecodeOption
		rule   RuleRef
		prefix string
	}{
		{"phase1", TrackGSM0902Phase1Form, RuleRef{Document: "GSM 09.02", Edition: "V3.11.0", Clause: "6.1"}, "GSM 09.02 V3.11.0 §6.1: "},
		{"phase2", TrackGSM0902Form, RuleRef{Document: "GSM 09.02", Edition: "V4.19.1", Clause: "14.1.1"}, "GSM 09.02 V4.19.1 §14.1.1: "},
		{"current", TrackMAPForm, RuleRef{Document: "3GPP TS 29.002", Edition: "V19.1.0", Clause: "17.1.1"}, "TS 29.002 §17.1.1: "},
	} {
		for _, form := range []struct {
			name string
			wire []byte
		}{
			{"short-length", []byte{4, 0x81, 1, 0x12}},
			{"minimum-length-octets", []byte{4, 0x82, 0, 1, 0x12}},
			{"primitive-octet-string", []byte{0x24, 3, 4, 1, 0x12}},
		} {
			t.Run(edition.name+"/"+form.name, func(t *testing.T) {
				rows, err := decodePhase1Profile(t, form.wire, true, false, edition.track)
				if err != nil || len(rows) != 1 {
					t.Fatalf("decode records=%+v error=%v", rows, err)
				}
				want := rows[0]
				if want.Kind != ProtocolRule || want.Rule != edition.rule || want.Constraint != edition.prefix+form.name || want.Path != "Value" || want.Source != "MAP-Test.Value" || want.ObservedValue != "received BER form" {
					t.Fatalf("decode record=%+v", want)
				}
				want.Offset, want.OctetOffset, want.ChildIndexes = nil, nil, nil
				decode := func(data []byte, opts ...DecodeOption) error {
					opts = edition.track(opts)
					data, err := OwnGeneratedBERInput(data, opts)
					if err != nil {
						return err
					}
					data, opts, err = PrepareGeneratedBERInput(data, opts)
					if err != nil {
						return err
					}
					opts = LocateDecodedElement(data, "MAP-Test.Value", opts)
					_, _, err = DecodeOctetString(data, opts...)
					return LocateDecodeError(err, opts)
				}
				var log ViolationLog
				if err := CheckMAPEncodedElement(form.wire, []EncodeOption{WithTolerance(&log)}, decode); err != nil {
					t.Fatal(err)
				}
				got := log.Snapshot()
				if len(got) != 1 || !reflect.DeepEqual(publicRepresentationRecord(got[0]), publicRepresentationRecord(want)) {
					t.Fatalf("encode records=%+v, want %+v", got, want)
				}
				err = CheckMAPEncodedElement(form.wire, nil, decode)
				var refusal *ValidationError
				if !errors.Is(err, ErrInvalidValue) || !errors.As(err, &refusal) || !reflect.DeepEqual(publicRepresentationRecord(refusal.Violation), publicRepresentationRecord(want)) {
					t.Fatalf("strict replay=%v, want %+v", err, want)
				}
			})
		}
	}
}

// Compare the public diagnostic contract without private retention bookkeeping.
func publicRepresentationRecord(v Violation) Violation {
	return Violation{Kind: v.Kind, Rule: v.Rule, Constraint: v.Constraint, Path: v.Path, Source: v.Source, ObservedLength: v.ObservedLength, ObservedValue: v.ObservedValue, ObservedValueLength: v.ObservedValueLength, Offset: v.Offset, OctetOffset: v.OctetOffset, ChildIndexes: v.ChildIndexes}
}

func TestMAPRepresentationEncodeCleanPath(t *testing.T) {
	data := []byte{4, 1, 0x12}
	node := &ReplayNode{state: &ReplayState{mapProfileChecked: true}}
	decode := func([]byte, ...DecodeOption) error { t.Fatal("clean encode called typed decoder"); return nil }
	if got := testing.AllocsPerRun(100, func() {
		if err := CheckMAPEncoded(data, node, nil, decode); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("clean replay allocated %g times", got)
	}
}

func TestMAPRepresentationRuleFilter(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    Violation
		want bool
	}{
		{"phase1", Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "GSM 09.02", Edition: "V3.11.0", Clause: "6.1"}}, true},
		{"phase2", Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "GSM 09.02", Edition: "V4.19.1", Clause: "14.1.1"}}, true},
		{"TS-edition-independent", Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "3GPP TS 29.002", Edition: "another edition", Clause: "17.1.1"}}, true},
		{"wrong-phase1-edition", Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "GSM 09.02", Edition: "V4.19.1", Clause: "6.1"}}, false},
		{"wrong-phase2-edition", Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "GSM 09.02", Edition: "V3.11.0", Clause: "14.1.1"}}, false},
		{"other-protocol-rule", Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "GSM 09.02", Edition: "V3.11.0", Clause: "6.4"}}, false},
		{"typed-constraint", Violation{Kind: ASN1Constraint, Rule: RuleRef{Document: "GSM 09.02", Edition: "V3.11.0", Clause: "6.1"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMAPRepresentationViolation(tc.v); got != tc.want {
				t.Fatalf("representation filter=%v, want %v", got, tc.want)
			}
		})
	}
}

func decodePhase1Profile(t *testing.T, data []byte, tolerant, bits bool, root func([]DecodeOption) []DecodeOption) ([]Violation, error) {
	t.Helper()
	var log ViolationLog
	var opts []DecodeOption
	if tolerant {
		opts = append(opts, WithTolerance(&log))
	}
	opts = root(opts)
	opts = TrackGSM0902Form(opts)
	opts = TrackMAPForm(opts)
	data, err := OwnGeneratedBERInput(data, opts)
	if err != nil {
		return nil, err
	}
	data, opts, err = PrepareGeneratedBERInput(data, opts)
	if err != nil {
		return nil, err
	}
	opts = LocateDecodedElement(data, "MAP-Test.Value", opts)
	if bits {
		_, _, _, err = DecodeBitString(data, opts...)
	} else {
		_, _, err = DecodeOctetString(data, opts...)
	}
	err = LocateDecodeError(err, opts)
	return log.Snapshot(), err
}

func TestPhase1ProfileThreeRules(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
		rule string
	}{
		{"short-length", []byte{4, 0x81, 1, 0x12}, "short-length"},
		{"minimum-length-octets", append([]byte{4, 0x82, 0, 128}, bytes.Repeat([]byte{1}, 128)...), "minimum-length-octets"},
		{"primitive-octet-string", []byte{0x24, 3, 4, 1, 0x12}, "primitive-octet-string"},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			for _, tolerant := range []bool{false, true} {
				rows, err := decodePhase1Profile(t, row.wire, tolerant, false, TrackGSM0902Phase1Form)
				var got Violation
				if tolerant {
					if err != nil || len(rows) != 1 {
						t.Fatalf("rows=%+v error=%v", rows, err)
					}
					got = rows[0]
				} else {
					var failure *ValidationError
					if !errors.As(err, &failure) {
						t.Fatalf("strict=%v", err)
					}
					got = failure.Violation
				}
				if got.Rule.Document != "GSM 09.02" || got.Rule.Edition != "V3.11.0" || got.Rule.Clause != "6.1" || got.Constraint != "GSM 09.02 V3.11.0 §6.1: "+row.rule {
					t.Fatalf("wrong source: %+v", got)
				}
			}
		})
	}
}

func TestPhase1ProfileDoesNotImposeOtherEditionRules(t *testing.T) {
	for _, wire := range [][]byte{{0x23, 4, 3, 2, 0, 0x80}, {0x23, 0x80, 3, 2, 0, 0x80, 0, 0}} {
		rows, err := decodePhase1Profile(t, wire, false, true, TrackGSM0902Phase1Form)
		if err != nil || len(rows) != 0 {
			t.Fatalf("constructed BIT STRING: rows=%v error=%v", rows, err)
		}
		_, err = decodePhase1Profile(t, wire, false, true, TrackGSM0902Form)
		if err == nil {
			t.Fatal("Phase 2 lost primitive BIT STRING rule")
		}
		_, err = decodePhase1Profile(t, wire, false, true, TrackMAPForm)
		if err == nil {
			t.Fatal("TS 29.002 lost primitive BIT STRING rule")
		}
	}
	for _, length := range []int{0, 1, 127, 128, 255, 256} {
		wire, err := EncodeOctetString(bytes.Repeat([]byte{1}, length))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodePhase1Profile(t, wire, false, false, TrackGSM0902Phase1Form); err != nil {
			t.Fatalf("length %d: %v", length, err)
		}
	}
	opts := TrackGSM0902Phase1Form(nil)
	wire := []byte{0x30, 0x80, 0, 0}
	data, err := OwnGeneratedBERInput(wire, opts)
	if err != nil {
		t.Fatal(err)
	}
	data, opts, err = PrepareGeneratedBERInput(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	opts = LocateDecodedElement(data, "MAP-Test.Empty", opts)
	if err := ValidateBERElement(data, opts...); err != nil {
		t.Fatalf("indefinite empty constructor: %v", err)
	}
	if err := LocateDecodeError(nil, opts); err != nil {
		t.Fatal(err)
	}
}

func TestPhase1ProfileImplicitConstructedStrings(t *testing.T) {
	for _, bits := range []bool{false, true} {
		for _, root := range []struct {
			name          string
			selectProfile func([]DecodeOption) []DecodeOption
			accept        bool
		}{
			{"phase1", TrackGSM0902Phase1Form, bits}, {"phase2", TrackGSM0902Form, false}, {"current", TrackMAPForm, false},
		} {
			t.Run(root.name, func(t *testing.T) {
				wire := []byte{0xa0, 3, 4, 1, 0x12}
				if bits {
					wire = []byte{0xa0, 4, 3, 2, 0, 0x80}
				}
				opts := root.selectProfile(nil)
				data, err := OwnGeneratedBERInput(wire, opts)
				if err != nil {
					t.Fatal(err)
				}
				data, opts, err = PrepareGeneratedBERInput(data, opts)
				if err != nil {
					t.Fatal(err)
				}
				opts = LocateDecodedElement(data, "MAP-Test.Implicit", opts)
				if bits {
					_, _, err = DecodeImplicitBitStringValue(true, data[2:], opts...)
				} else {
					_, err = DecodeImplicitOctetStringValue(true, data[2:], opts...)
				}
				err = LocateDecodeError(err, opts)
				if (err == nil) != root.accept {
					t.Fatalf("bits=%t accept=%t error=%v", bits, root.accept, err)
				}
			})
		}
	}
}

func TestPhase1ProfileCannotReplaceAnExistingRoot(t *testing.T) {
	for _, root := range []func([]DecodeOption) []DecodeOption{TrackGSM0902Form, TrackMAPForm, func(opts []DecodeOption) []DecodeOption { return TrackMAPSyntax(opts, false) }} {
		opts := root(nil)
		before, err := decodeOptions(opts)
		if err != nil {
			t.Fatal(err)
		}
		selected := before.form.mapSyntax
		opts = TrackGSM0902Phase1Form(opts)
		after, err := decodeOptions(opts)
		if err != nil {
			t.Fatal(err)
		}
		if after.form.mapSyntax != selected || after.form.mapSyntax&mapSyntaxPhase1 != 0 {
			t.Fatal("nested Phase 1 codec changed the existing root profile")
		}
	}
}
