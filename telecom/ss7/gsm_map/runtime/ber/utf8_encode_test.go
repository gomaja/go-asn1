// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_encode_test.go; SHA-256 64cf51cb1fdb53c8b87d7c22717b33b57c7d3735b5718dcc4b50a614a3195727.
package ber

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §8.23.10 requires shortest-form UTF-8 scalar text.
func TestEncodeUTF8StringRejectsInvalidText(t *testing.T) {
	for _, encode := range []func(string) ([]byte, error){
		EncodeUTF8String,
		func(s string) ([]byte, error) { return EncodeStringTag(12, s) },
		func(s string) ([]byte, error) { return EncodeStringTagChecked(12, s) },
		func(s string) ([]byte, error) { return EncodeStringValueTagChecked(12, s) },
	} {
		if _, err := encode("\xff"); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("invalid UTF-8 error = %v", err)
		}
	}
	for _, tagNum := range []int{28, 30} {
		if _, err := EncodeStringTagChecked(tagNum, "\xff"); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("tag %d error = %v", tagNum, err)
		}
	}
}

// Builds deliberately malformed received wire without the validated encoder.
func encodeUTF8WireForTest(t *testing.T, value string) []byte {
	t.Helper()
	return mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, []byte(value)))
}

// Explicit encoding-rule checks use typed text, not an encoded TLV or a
// preformatted observation. Repeated bad octets remain distinct records.
func TestEncodedUTF8RuleUsesTypedContents(t *testing.T) {
	rule := RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}
	const source = "Module.Record.text"
	for _, text := range []string{"a", "é", "\xff", "\xff\xff"} {
		var reports ViolationLog
		options, finish := StageEncodeReports([]EncodeOption{WithTolerance(&reports)})
		err := CheckEncodedValue(EncodeRule(options, source, rule), "text", "UTF8String shortest-form UTF-8 scalar text (X.690 (02/2021) §8.23.10)", text)
		finish(err == nil)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if text[0] == 255 {
			want = len(text)
		}
		records := reports.Snapshot()
		if len(records) != want {
			t.Fatalf("%q: %d records, want %d", text, len(records), want)
		}
		for _, record := range records {
			if record.Path != "text" || record.Source != source || record.Rule != rule || record.ObservedValue != "ff" || record.Offset != nil || record.OctetOffset != nil || len(record.ChildIndexes) != 0 {
				t.Fatalf("record=%+v", record)
			}
		}
	}
}
