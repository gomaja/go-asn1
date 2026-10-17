// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/utf8_validation_test.go; SHA-256 2df50ff87ff19ee76f6090704b71b9a5c7b639e3f3289a3f18c7347770963689.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
	"unicode/utf8"
)

func TestUTF8StringAcceptsSplitScalars(t *testing.T) {
	for _, wireText := range []string{"0c00", "0c07efbfbdf48fbfbf", "2c090401e20401820401ac", "2c800401f0248004019004018000000401800000", "2c0404002400"} {
		wire := structureWire(t, wireText)
		if err := ValidateBERElement(wire); err != nil {
			t.Fatalf("%s: %v", wireText, err)
		}
		text, n, err := DecodeString(wire, tag.TagUTF8String)
		if err != nil || n != len(wire) || !utf8.ValidString(text) {
			t.Fatalf("%s: %x n=%d err=%v", wireText, text, n, err)
		}
	}
	// OCTET STRING does not impose a character repertoire.
	if err := ValidateBERElement(structureWire(t, "0401ff")); err != nil {
		t.Fatal(err)
	}
}

func FuzzUTF8StringValidation(f *testing.F) {
	for _, text := range []string{"", "ff", "c080", "eda080", "e282", "e282ac", "f48fbfbf"} {
		f.Add(structureWire(f, text))
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) > 4096 {
			t.Skip()
		}
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, contents))
		scanErr := ValidateBERElement(wire)
		got, _, decodeErr := DecodeString(wire, tag.TagUTF8String)
		if (scanErr == nil) != utf8.Valid(contents) || (decodeErr == nil) != utf8.Valid(contents) {
			t.Fatalf("UTF-8 agreement: scan=%v typed=%v", scanErr, decodeErr)
		}
		if decodeErr == nil && !bytes.Equal([]byte(got), contents) {
			t.Fatal("valid text changed")
		}
		split := len(contents) / 2
		fragments := append(mustEncode(t)(EncodeOctetString(contents[:split])), mustEncode(t)(EncodeOctetString(contents[split:]))...)
		wire = mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String, Constructed: true}, fragments))
		if err := ValidateBERElement(wire); (err == nil) != utf8.Valid(contents) {
			t.Fatalf("segmented text: %v", err)
		}
		var reports ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: max(1, len(contents))})})
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatal(err)
		}
		got, _, err := DecodeString(wire, tag.TagUTF8String, ChildDecodeOptions(options, "text")...)
		if err != nil || !bytes.Equal([]byte(got), contents) {
			t.Fatalf("tolerant text: %v", err)
		}
		finish(true)
		wantReports := 0
		// Go's string iteration replaces each malformed octet independently;
		// an actually encoded U+FFFD is valid and must not produce a report.
		for offset, r := range string(contents) {
			if r == utf8.RuneError && !bytes.HasPrefix(contents[offset:], []byte{0xef, 0xbf, 0xbd}) {
				wantReports++
			}
		}
		if len(reports.Snapshot()) != wantReports {
			t.Fatal("wrong report count")
		}
		for _, record := range reports.Snapshot() {
			if record.Path != "text" || record.OctetOffset == nil {
				t.Fatal("preflight and typed decoding did not share the qualified record")
			}
		}
	})
}
