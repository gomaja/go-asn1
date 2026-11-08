// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/gsm0902_profile_test.go; SHA-256 6d4895394ce0822cea454283b1c7c015dd3fcff0bd49f755ed2e603a2d9a1c2e.
package ber

import (
	"errors"
	"testing"
)

func TestGSM0902ProfileCitationAndRootChoice(t *testing.T) {
	for _, tolerant := range []bool{false, true} {
		var log ViolationLog
		var opts []DecodeOption
		if tolerant {
			opts = append(opts, WithTolerance(&log))
		}
		opts = TrackGSM0902Form(opts)
		opts = TrackMAPForm(opts) // A nested codec cannot replace the root edition.
		wire := []byte{4, 0x81, 1, 0x12}
		data, err := OwnGeneratedBERInput(wire, opts)
		if err != nil {
			t.Fatal(err)
		}
		data, opts, err = PrepareGeneratedBERInput(data, opts)
		if err != nil {
			t.Fatal(err)
		}
		opts = LocateDecodedElement(data, "MAP-CommonDataTypes.IMSI", opts)
		if _, _, err := DecodeOctetString(data, opts...); err != nil {
			t.Fatal(err)
		}
		err = LocateDecodeError(nil, opts)
		var got Violation
		if tolerant {
			rows := log.Snapshot()
			if err != nil || len(rows) != 1 {
				t.Fatalf("reports=%+v err=%v", rows, err)
			}
			got = rows[0]
		} else {
			var refusal *ValidationError
			if !errors.As(err, &refusal) {
				t.Fatalf("strict=%v", err)
			}
			got = refusal.Violation
		}
		if got.Rule.Document != "GSM 09.02" || got.Rule.Edition != "V4.19.1" || got.Rule.Clause != "14.1.1" || got.Constraint != "GSM 09.02 V4.19.1 §14.1.1: short-length" {
			t.Fatalf("wrong historical source: %+v", got)
		}
	}
	if err := ValidateBERElement([]byte{5, 0}, TrackGSM0902Form(nil)...); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("standalone profile=%v", err)
	}
	generic := TrackMAPSyntax(nil, false)
	generic = TrackGSM0902Form(generic)
	config, err := decodeOptions(generic)
	if err != nil || config.form.mapProfile() {
		t.Fatalf("nested historical codec changed generic root: %v", err)
	}
}
