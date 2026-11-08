// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/unicode_noncharacters_test.go; SHA-256 b7624d97901d8d83bbf388878268bcbc972e770054ea1fcbc8fb9bc33f83f538.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"strings"
	"testing"
)

// Enumerate ISO/IEC 10646:2003 §§7 a),8 independently of runtime predicates.
func noncharacterTestRunes() []rune {
	var values []rune
	for plane := rune(0); plane <= 0x10; plane++ {
		values = append(values, plane*0x10000+0xfffe, plane*0x10000+0xffff)
	}
	for cell := rune(0xfdd0); cell <= 0xfdef; cell++ {
		values = append(values, cell)
	}
	return values
}

func TestUnicodeNoncharacters(t *testing.T) {
	invalid := noncharacterTestRunes()
	if len(invalid) != 66 {
		t.Fatal("wrong independent noncharacter count")
	}
	for _, number := range []int{tag.TagBMPString, tag.TagUniversalString, tag.TagUTF8String} {
		for _, r := range invalid {
			if number == tag.TagBMPString && r > 0xffff {
				if _, err := EncodeStringTagChecked(number, string(r)); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("supplementary BMP noncharacter U+%X: %v", r, err)
				}
				continue
			}
			t.Run(fmt.Sprintf("%d/U+%04X", number, r), func(t *testing.T) { checkUnicodeRepertoire(t, number, r, false) })
		}
		// U+0378 and U+2FE0 are unassigned in the referenced edition; no assignment lookup is imposed.
		for _, r := range []rune{0x0378, 0x2fe0, 0xfdcf, 0xfdf0, 0xfffd, 0x1fffd, 0x10fffd} {
			if number == tag.TagBMPString && r > 0xffff {
				continue
			}
			t.Run(fmt.Sprintf("allowed/%d/U+%04X", number, r), func(t *testing.T) { checkUnicodeRepertoire(t, number, r, true) })
		}
	}
}

func checkUnicodeRepertoire(t *testing.T, number int, r rune, valid bool) {
	t.Helper()
	text := string(r)
	contents := controlContents(number, text)
	wire := append([]byte{byte(number), byte(len(contents))}, contents...)
	check := func(label string, err error, accept bool) {
		t.Helper()
		if accept && err != nil || !accept && !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: %v; accept=%v", label, err, accept)
		}
	}
	check("DER", ValidateDEREncodedElement(wire), valid)
	decoded, err := DecodeStringValueTag(number, contents)
	check("contents decode", err, valid)
	if valid && decoded != text {
		t.Fatal("contents changed")
	}
	for _, encode := range []func() ([]byte, error){func() ([]byte, error) { return EncodeStringTagChecked(number, text) }, func() ([]byte, error) { return EncodeStringValueTagChecked(number, text) }} {
		_, err := encode()
		check("typed encode", err, valid)
	}
	wires := [][]byte{wire}
	for split := 0; split <= len(contents); split++ {
		segments := append([]byte{4, byte(split)}, contents[:split]...)
		segments = append(segments, 4, byte(len(contents)-split))
		segments = append(segments, contents[split:]...)
		wires = append(wires, append([]byte{byte(number) | 32, byte(len(segments))}, segments...))
		indefinite := append([]byte{byte(number) | 32, 128}, segments...)
		wires = append(wires, append(indefinite, 0, 0))
	}
	for i, input := range wires {
		check(fmt.Sprintf("BER/%d", i), ValidateBERElement(input), valid)
		got, n, err := DecodeString(input, number)
		check("typed decode", err, valid)
		if valid && (got != text || n != len(input)) {
			t.Fatal("typed value changed")
		}
		for _, scan := range []bool{true, false} {
			var log ViolationLog
			options := []DecodeOption{WithTolerance(&log)}
			tolerated := valid || number == tag.TagUTF8String
			if scan {
				err = ValidateBERElement(input, options...)
			} else {
				got, n, err = DecodeString(input, number, options...)
			}
			check("tolerant", err, tolerated)
			if tolerated && !scan && (got != text || n != len(input)) {
				t.Fatal("tolerant value changed")
			}
			if tolerated {
				want := 0
				if !valid {
					want = 1
				}
				records := log.Snapshot()
				if len(records) != want {
					t.Fatalf("reports=%d want=%d", len(records), want)
				}
				if want != 0 && (records[0].Rule.Document != "ISO/IEC 10646" || records[0].Rule.Edition != "2003" || records[0].Rule.Clause != "7 a), 8") {
					t.Fatal("wrong noncharacter rule")
				}
				if want != 0 && (records[0].OctetOffset == nil || *records[0].OctetOffset != 0) {
					t.Fatal("noncharacter offset changed")
				}
			}
		}
	}
}

// ISO/IEC 2022:1994 §13.1 requires a final byte; these incomplete escapes stay accepted.
func TestIncompleteEscapeAcceptance(t *testing.T) {
	for _, number := range []int{tag.TagBMPString, tag.TagUniversalString, tag.TagUTF8String, tag.TagIA5String} {
		for _, text := range []string{"tail\x1b", "\x1b !", "\x1b\n", "\x1b\x00"} {
			contents := controlContents(number, text)
			wire := append([]byte{byte(number), byte(len(contents))}, contents...)
			t.Run(fmt.Sprintf("%d/%x", number, text), func(t *testing.T) { checkControlWire(t, wire, text, false) })
		}
		// The first constructed leaf ends with ESC, then a control cancels it.
		text := "\x1b\n"
		contents := controlContents(number, text)
		t.Run(fmt.Sprintf("segment/%d", number), func(t *testing.T) {
			checkControlWire(t, append([]byte{byte(number), byte(len(contents))}, contents...), text, false)
		})
	}
}

// X.690 (02/2021) §8.23.5.3 excludes escape sequences, not standalone IA5 SI/SO.
func TestIA5ShiftAcceptance(t *testing.T) {
	for _, text := range []string{"\x0e", "\x0f", "a\x0e\x0fb"} {
		wire := append([]byte{22, byte(len(text))}, []byte(text)...)
		checkControlWire(t, wire, text, false)
	}
}

func TestUnicodeNoncharacterAcceptedNeighborEncoding(t *testing.T) {
	for _, number := range []int{tag.TagBMPString, tag.TagUniversalString, tag.TagUTF8String} {
		wire, err := EncodeStringTagChecked(number, "\ufdcf\ufdf0\ufffd")
		expected := controlContents(number, "\ufdcf\ufdf0\ufffd")
		if err != nil || !bytes.Equal(wire, append([]byte{byte(number), byte(len(expected))}, expected...)) {
			t.Fatalf("neighbor encoding: %v", err)
		}
	}
}

// The repertoire scan retains bounded state as the number of excluded cells grows.
func TestUnicodeNoncharacterScanGrowth(t *testing.T) {
	for _, number := range []int{tag.TagBMPString, tag.TagUniversalString, tag.TagUTF8String} {
		var initial float64
		for _, n := range []int{64, 256, 1024, 4096} {
			wire, err := EncodeTLV(tag.Tag{Number: number}, controlContents(number, strings.Repeat("\ufdd0", n)))
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateBERElement(wire); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("tag=%d n=%d: %v", number, n, err)
			}
			// The race detector may discard pooled state between samples.
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
