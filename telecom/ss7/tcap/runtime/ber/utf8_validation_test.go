// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/utf8_validation_test.go; SHA-256 cf956a759ee9fee71cbfedfed583f69054ed470185c7db714e594388f85bfbb9.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"regexp"
	"testing"
	"unicode/utf8"
)

func TestUTF8StringAcceptsSplitScalars(t *testing.T) {
	for _, wireText := range []string{"0c00", "0c07efbfbdf48fbfbd", "2c090401e20401820401ac", "2c800401f0248004019004018000000401800000", "2c0404002400"} {
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

// Independently describe the forbidden UTF8 character sequences using a regular
// expression, alongside the standard library's scalar/shortest-form oracle.
var forbiddenUTF8Controls = regexp.MustCompile(`\x1b[\x20-\x2f]*[\x30-\x7e]|[\x0e\x0f\x{008e}\x{008f}]`)

func FuzzUTF8StringValidation(f *testing.F) {
	for _, text := range []string{"", "ff", "c080", "eda080", "e282", "e282ac", "f48fbfbf", "efb790", "efb7af", "efb78f", "efb7b0", "1b4e", "1b204c", "0e", "c28e", "1b", "0d0a"} {
		f.Add(structureWire(f, text))
	}
	noncharacters := map[rune]bool{}
	for _, r := range noncharacterTestRunes() {
		noncharacters[r] = true
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) > 4096 {
			t.Skip()
		}
		forbidden := forbiddenUTF8Controls.FindAllIndex(contents, -1)
		valid := utf8.Valid(contents) && len(forbidden) == 0
		for _, r := range string(contents) {
			if noncharacters[r] {
				valid = false
			}
		}
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, contents))
		scanErr := ValidateBERElement(wire)
		got, _, decodeErr := DecodeString(wire, tag.TagUTF8String)
		if (scanErr == nil) != valid || (decodeErr == nil) != valid {
			t.Fatalf("UTF-8 agreement: scan=%v typed=%v", scanErr, decodeErr)
		}
		if decodeErr == nil && !bytes.Equal([]byte(got), contents) {
			t.Fatal("valid text changed")
		}
		split := len(contents) / 2
		fragments := append(mustEncode(t)(EncodeOctetString(contents[:split])), mustEncode(t)(EncodeOctetString(contents[split:]))...)
		wire = mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String, Constructed: true}, fragments))
		if err := ValidateBERElement(wire); (err == nil) != valid {
			t.Fatalf("segmented text: %v", err)
		}
		var reports ViolationLog
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: max(1, len(contents))})})
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatal(err)
		}
		got, _, err := DecodeString(wire, tag.TagUTF8String, ChildDecodeOptions(options, "text")...)
		if err != nil || !bytes.Equal([]byte(got), contents) {
			t.Fatalf("tolerant text: %v", err)
		}
		finish(true)
		wantReports := len(forbidden)
		// Go's string iteration replaces each malformed octet independently;
		// an actually encoded U+FFFD is valid and must not produce a report.
		for offset, r := range string(contents) {
			if r == utf8.RuneError && !bytes.HasPrefix(contents[offset:], []byte{0xef, 0xbf, 0xbd}) || noncharacters[r] {
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
