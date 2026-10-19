// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_validation_test.go; SHA-256 e7fb9d3ae6bed9285405bd9f01a5681e4483daf2dfab5e0cd4cd15dcb19f1e1e.
package ber

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §§8.23.3, 8.23.10: fragments are OCTET STRINGs,
// and their concatenation must be shortest-form UTF-8 scalar text.
func TestUTF8StringRejectsInvalidContents(t *testing.T) {
	for _, text := range []string{"ff", "80", "c080", "e08080", "f0808080", "eda080", "edbfbf", "f4908080", "e282", "f09f92", "fe", "ff4142"} {
		t.Run(text, func(t *testing.T) {
			contents := structureWire(t, text)
			primitive := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, contents))
			fragments := mustEncode(t)(EncodeOctetString(contents))
			constructed := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String, Constructed: true}, fragments))
			for _, wire := range [][]byte{primitive, constructed} {
				if err := ValidateBERElement(wire); !errors.Is(err, ErrInvalidValue) {
					t.Errorf("validator %x: %v", wire, err)
				}
				if _, _, err := DecodeString(wire, tag.TagUTF8String); !errors.Is(err, ErrInvalidValue) {
					t.Errorf("typed %x: %v", wire, err)
				}
			}
			for _, form := range []bool{false, true} {
				value := contents
				if form {
					value = fragments
				}
				if _, err := DecodeImplicitStringValue(tag.TagUTF8String, form, value); !errors.Is(err, ErrInvalidValue) {
					t.Errorf("implicit constructed=%t: %v", form, err)
				}
			}
			if _, err := DecodeStringValueTag(tag.TagUTF8String, contents); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("contents: %v", err)
			}
		})
	}
}

func TestUTF8StringToleranceRetainsOctets(t *testing.T) {
	for _, wireText := range []string{"0c01ff", "0c02c080", "0c03eda080", "0c02e282", "2c070401e2040282ff", "2c800401ff0000"} {
		wantReports := map[string]int{"0c01ff": 1, "0c02c080": 2, "0c03eda080": 3, "0c02e282": 2, "2c070401e2040282ff": 3, "2c800401ff0000": 1}[wireText]
		wire := structureWire(t, wireText)
		_, _, contents, err := DecodeTLV(wire)
		if err != nil {
			t.Fatal(err)
		}
		constructed := wire[0]&0x20 != 0
		want := contents
		if constructed {
			want, err = DecodeImplicitOctetStringValue(true, contents)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, entry := range []string{"preflight", "typed", "implicit"} {
			t.Run(wireText+"/"+entry, func(t *testing.T) {
				var reports ViolationLog
				options := TrackBERForm(ChildDecodeOptions([]DecodeOption{WithTolerance(&reports)}, "message"))
				options = ChildDecodeOptions(options, "text")
				switch entry {
				case "preflight":
					err = ValidateBERElement(wire, options...)
				case "typed":
					var got string
					var n int
					got, n, err = DecodeString(wire, tag.TagUTF8String, options...)
					if n != len(wire) || !bytes.Equal([]byte(got), want) {
						t.Errorf("decoded %x n=%d want %x", got, n, want)
					}
					replay, encodeErr := EncodeUTF8String(got)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					if !bytes.Equal(replay[2:], want) {
						t.Errorf("octets changed: %x", replay)
					}
				case "implicit":
					var got string
					got, err = DecodeImplicitStringValue(tag.TagUTF8String, constructed, contents, options...)
					if !bytes.Equal([]byte(got), want) {
						t.Errorf("decoded %x want %x", got, want)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				records := reports.Snapshot()
				if len(records) != wantReports || records[0].Path != "message.text" || !strings.Contains(records[0].Constraint, "UTF8String") {
					t.Errorf("reports: %+v", records)
				}
				if !BERNeedsPreservation(options) {
					t.Error("tolerated text did not retain received-form marker")
				}
			})
		}
	}
	// Tolerance never admits a malformed segment structure.
	var reports ViolationLog
	if err := ValidateBERElement(structureWire(t, "2c030c01ff"), WithTolerance(&reports)); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("invalid segment: %v", err)
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed scan published reports")
	}
}

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
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: max(1, len(contents))})})
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
