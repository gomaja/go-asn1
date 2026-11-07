// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/restricted_controls_test.go; SHA-256 868b21125cd07c37ad28dc50c0aa5a5afaf814f2579b6a0ccf9fdcd0de99b363.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §§8.23.5.3, 8.23.9–8.23.10;
// ISO/IEC 2022:1994 §§7.3, 13.1–13.2; ISO/IEC 10646:2003 §§15–16.
func TestRestrictedControlIssueVectors(t *testing.T) {
	for _, row := range []struct {
		wire, text string
		invalid    bool
	}{
		{"1e02000e", "\x0e", true}, {"1e02000f", "\x0f", true},
		{"1c040000000e", "\x0e", true}, {"1e04001b004e", "\x1bN", true},
		{"1c080000001b0000004e", "\x1bN", true}, {"0c021b4e", "\x1bN", true},
		{"16021b4e", "\x1bN", true}, {"1e02000a", "\n", false}, {"16020d0a", "\r\n", false},
	} {
		wire, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(row.wire, func(t *testing.T) { checkControlWire(t, wire, row.text, row.invalid) })
	}
}

func controlContents(number int, text string) []byte {
	var b []byte
	for _, r := range text {
		switch number {
		case tag.TagBMPString:
			b = append(b, byte(r>>8), byte(r))
		case tag.TagUniversalString:
			b = append(b, byte(r>>24), byte(r>>16), byte(r>>8), byte(r))
		default:
			b = append(b, []byte(string(r))...)
		}
	}
	return b
}

func checkControlWire(t *testing.T, wire []byte, text string, invalid bool) {
	t.Helper()
	number := int(wire[0])
	contents := wire[2:]
	check := func(label string, err error, want bool) {
		t.Helper()
		if want && !errors.Is(err, ErrInvalidValue) || !want && err != nil {
			t.Errorf("%s: %v, invalid=%v", label, err, want)
		}
	}
	check("BER", ValidateBERElement(wire), invalid)
	check("DER", ValidateDEREncodedElement(wire), invalid)
	_, err := DecodeStringValueTag(number, contents)
	check("contents decode", err, invalid)
	encoded, err := EncodeStringTagChecked(number, text)
	check("encode", err, invalid)
	if !invalid && !bytes.Equal(encoded, wire) {
		t.Fatal("valid encoding changed")
	}
	_, err = EncodeStringValueTagChecked(number, text)
	check("contents encode", err, invalid)
	// Split at every octet, including inside fixed-width characters and escape sequences.
	for split := 0; split <= len(contents); split++ {
		segments := append([]byte{4, byte(split)}, contents[:split]...)
		segments = append(segments, 4, byte(len(contents)-split))
		segments = append(segments, contents[split:]...)
		constructed := append([]byte{byte(number) | 32, byte(len(segments))}, segments...)
		indefinite := append([]byte{byte(number) | 32, 128}, segments...)
		indefinite = append(indefinite, 0, 0)
		for _, input := range [][]byte{wire, constructed, indefinite} {
			check("segmented BER", ValidateBERElement(input), invalid)
			_, _, err := DecodeString(input, number)
			check("typed decode", err, invalid)
			for _, scan := range []bool{false, true} {
				var log ViolationLog
				options := []DecodeOption{WithTolerance(&log)}
				if scan {
					err = ValidateBERElement(input, options...)
				} else {
					_, _, err = DecodeString(input, number, options...)
				}
				tolerable := number == tag.TagIA5String || number == tag.TagUTF8String
				check("tolerant", err, invalid && !tolerable)
				if invalid && tolerable && len(log.Snapshot()) != 1 {
					t.Errorf("scan=%v split=%d reports=%d", scan, split, len(log.Snapshot()))
				}
			}
		}
	}
}

func TestRestrictedControlSequences(t *testing.T) {
	for _, number := range []int{tag.TagBMPString, tag.TagUniversalString, tag.TagUTF8String, tag.TagIA5String} {
		for _, text := range []string{"\x1bN", "\x1bO", "\x1bn", "\x1bo", "\x1b|", "\x1b}", "\x1b~", "\x1b(B", "\x1b$)A", "\x1b%/F", "\x1b%@", "\x1b L", "\x1b!@", "\x1b\"C"} {
			contents := controlContents(number, text)
			wire := append([]byte{byte(number), byte(len(contents))}, contents...)
			t.Run(fmt.Sprintf("%d/%x", number, text), func(t *testing.T) { checkControlWire(t, wire, text, true) })
		}
		if number != tag.TagIA5String {
			for _, text := range []string{"\x0e", "\x0f", "\u008e", "\u008f"} {
				contents := controlContents(number, text)
				wire := append([]byte{byte(number), byte(len(contents))}, contents...)
				t.Run(fmt.Sprintf("%d/%x", number, text), func(t *testing.T) { checkControlWire(t, wire, text, true) })
			}
		}
		if number == tag.TagBMPString || number == tag.TagUniversalString {
			for _, text := range []string{"\u009b1;2 m", "\x1b[1;2 m"} {
				contents := controlContents(number, text)
				wire := append([]byte{byte(number), byte(len(contents))}, contents...)
				t.Run(fmt.Sprintf("%d/%x", number, text), func(t *testing.T) { checkControlWire(t, wire, text, true) })
			}
		}
		// Retain incomplete ESC inputs while their handling is decided separately.
		valid := []string{"\t\r\n", "plain", "\x00", "\x1b", "\x1b ", "\x1b\n"}
		if number == tag.TagBMPString || number == tag.TagUniversalString {
			valid = append(valid, "\x1bD", "\u009b31m", "\x1b[31m", "\u010e\u010f\u011bN", "\ufdd0")
		}
		if number == tag.TagIA5String {
			valid = append(valid, "\x0e\x0f")
		}
		for _, text := range valid {
			contents := controlContents(number, text)
			wire := append([]byte{byte(number), byte(len(contents))}, contents...)
			t.Run(fmt.Sprintf("allowed/%d/%x", number, text), func(t *testing.T) { checkControlWire(t, wire, text, false) })
		}
	}
}

// Character recognition retains constant state even for arbitrarily many
// intermediates or subset parameters. This checks allocation counts, not timing.
func TestRestrictedControlScanGrowth(t *testing.T) {
	for _, number := range []int{tag.TagBMPString, tag.TagUniversalString, tag.TagUTF8String, tag.TagIA5String} {
		var initial float64
		for _, n := range []int{64, 256, 1024, 4096} {
			text := "\x1b" + strings.Repeat(" ", n) + "L"
			contents := controlContents(number, text)
			wire, err := EncodeTLV(tag.Tag{Number: number}, contents)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateBERElement(wire); !errors.Is(err, ErrInvalidValue) {
				t.Fatal("missed long escape sequence")
			}
			// The race detector randomly drops sync.Pool entries, making allocation counts unstable.
			if raceEnabled {
				continue
			}
			allocs := testing.AllocsPerRun(3, func() { _ = ValidateBERElement(wire) })
			if n == 64 {
				initial = allocs
			} else if allocs > initial+1 {
				t.Fatalf("tag=%d n=%d allocations %.0f > initial %.0f + 1", number, n, allocs, initial)
			}
		}
	}
}

// Explicit IA5 tolerance keeps the same repertoire policy when replay is
// disabled: current typed contents are emitted and the violation is reported.
func TestIA5ControlToleranceWithoutReplay(t *testing.T) {
	var alphabet, controls ViolationLog
	// This is the native generated alphabet check for one offending octet.
	options := []EncodeOption{WithTolerance(&alphabet), WithoutBERReplay()}
	if err := CheckEncodedValue(options, "text", "IA5String character repertoire", "0xFF"); err != nil || len(alphabet.Snapshot()) != 1 {
		t.Fatal("native alphabet tolerance changed")
	}
	options = []EncodeOption{WithTolerance(&controls), WithoutBERReplay()}
	if err := checkEncodedIA5Controls("\x1bN", options, "text"); err != nil || len(controls.Snapshot()) != 1 {
		t.Fatalf("control tolerance differs from repertoire: %v, reports=%d", err, len(controls.Snapshot()))
	}
}
