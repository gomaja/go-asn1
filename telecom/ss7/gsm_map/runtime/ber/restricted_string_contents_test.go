// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/restricted_string_contents_test.go; SHA-256 a7339c3de917f405cfc18656d7c9159308c23a1154a8aa4cc0a729d31c110d8f.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func assertRestrictedSentinels(t *testing.T, err error, invalid bool) {
	t.Helper()
	for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit, ErrInvalidCodec, ErrInvalidBinding} {
		if got, want := errors.Is(err, sentinel), invalid && sentinel == ErrInvalidValue; got != want {
			t.Errorf("error %v: errors.Is(%v)=%v want %v", err, sentinel, got, want)
		}
	}
	if !invalid && err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// X.690 (02/2021) §§8.23.1, 8.23.4–8.23.8, 8.25;
// X.680 (02/2021) §§41.2, 41.4, 46.3, 47.3.
func TestRestrictedContentsIssueVectors(t *testing.T) {
	for _, row := range []struct {
		wire               string
		invalid, tolerable bool
	}{
		{"1e0100", true, false}, {"1e03004100", true, false}, {"1c03000000", true, false}, {"1c0500000041ff", true, false},
		{"1e020041", false, false}, {"1e00", false, false}, {"1c0400000041", false, false},
		{"120141", true, true}, {"130121", true, true}, {"1601ff", true, true}, {"1a01ff", true, true},
		{"1701ff", true, false}, {"1801ff", true, false}, {"0c01ff", true, true},
		{"1e02d800", true, false}, {"1e02dfff", true, false}, {"1e02d7ff", false, false}, {"1e02e000", false, false},
		{"1c040000d800", true, false}, {"1c040000dfff", true, false}, {"1c0400110000", true, false},
		{"1c040010ffff", false, false}, {"1c04ffffffff", true, false},
	} {
		t.Run(row.wire, func(t *testing.T) {
			wire := structureWire(t, row.wire)
			number := int(wire[0])
			assertRestrictedSentinels(t, ValidateBERElement(wire), row.invalid)
			assertRestrictedSentinels(t, ValidateDEREncodedElement(wire), row.invalid)
			_, _, err := decodeRestrictedTest(wire, number)
			assertRestrictedSentinels(t, err, row.invalid)
			for _, scan := range []bool{true, false} {
				var log ViolationLog
				opts := ChildDecodeOptions(ChildDecodeOptions([]DecodeOption{WithTolerance(&log)}, "message"), "text")
				if scan {
					err = ValidateBERElement(wire, opts...)
				} else {
					_, _, err = decodeRestrictedTest(wire, number, opts...)
				}
				assertRestrictedSentinels(t, err, row.invalid && !row.tolerable)
				reports := log.Snapshot()
				want := 0
				if row.invalid && row.tolerable {
					want = 1
				}
				if len(reports) != want {
					t.Fatalf("scan=%v: reports=%+v want %d", scan, reports, want)
				}
				if want != 0 && reports[0].Path != "message.text" {
					t.Errorf("Path=%q", reports[0].Path)
				}
			}
		})
	}
}

func decodeRestrictedTest(wire []byte, number int, opts ...DecodeOption) (string, int, error) {
	switch number {
	case tag.TagUTCTime:
		v, n, e := DecodeUTCTime(wire, opts...)
		return v.String(), n, e
	case tag.TagGeneralizedTime:
		v, n, e := DecodeGeneralizedTime(wire, opts...)
		return v.String(), n, e
	default:
		return DecodeString(wire, number, opts...)
	}
}

func TestRestrictedAlphabetBoundaries(t *testing.T) {
	for _, number := range []int{18, 19, 22, 26} {
		for n := 0; n < 256; n++ {
			b := byte(n)
			// Independently enumerate X.680 Tables 8–10 and X.690 Table 3.
			var legal bool
			switch number {
			case 18:
				legal = strings.ContainsRune(" 0123456789", rune(b))
			case 19:
				legal = strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?", rune(b))
			case 22:
				legal = n < 128
			case 26:
				legal = n >= 32 && n <= 126
			}
			t.Run(fmt.Sprintf("tag%d/octet%d", number, n), func(t *testing.T) {
				wire := []byte{byte(number), 1, b}
				assertRestrictedSentinels(t, ValidateBERElement(wire), !legal)
				assertRestrictedSentinels(t, ValidateDEREncodedElement(wire), !legal)
				_, _, e := DecodeString(wire, number)
				assertRestrictedSentinels(t, e, !legal)
				_, e = DecodeStringValueTag(number, wire[2:])
				assertRestrictedSentinels(t, e, !legal)
				for _, encode := range []func(int, string) ([]byte, error){EncodeStringTag, EncodeStringTagChecked, EncodeStringValueTagChecked} {
					_, e = encode(number, string([]byte{b}))
					assertRestrictedSentinels(t, e, !legal)
				}
				if number == 22 {
					_, e = EncodeIA5String(string([]byte{b}))
					assertRestrictedSentinels(t, e, !legal)
				}
				if number == 19 {
					_, e = EncodePrintableString(string([]byte{b}))
					assertRestrictedSentinels(t, e, !legal)
				}
			})
		}
	}
}

func TestRestrictedTimeForms(t *testing.T) {
	for _, number := range []int{23, 24} {
		var values []string
		if number == 23 {
			for _, base := range []string{"2601020304", "260102030405"} {
				for _, zone := range []string{"Z", "+0000", "-0000", "+2359", "-0530"} {
					values = append(values, base+zone)
				}
			}
		} else {
			for _, base := range []string{"2026010203", "202601020304", "20260102030405"} {
				for _, fraction := range []string{"", ".0", ",123456789012345678901234567890"} {
					for _, zone := range []string{"", "Z", "+00", "-05", "+0000", "-2359"} {
						values = append(values, base+fraction+zone)
					}
				}
			}
		}
		for _, value := range values {
			t.Run(fmt.Sprintf("tag%d/%s", number, value), func(t *testing.T) {
				wire := append([]byte{byte(number), byte(len(value))}, value...)
				assertRestrictedSentinels(t, ValidateBERElement(wire), false)
				got, n, e := decodeRestrictedTest(wire, number)
				assertRestrictedSentinels(t, e, false)
				if got != value || n != len(wire) {
					t.Errorf("got %q,%d want %q,%d", got, n, value, len(wire))
				}
				// These controls deliberately omit seconds, use local time, offset,
				// comma, or a trailing fractional zero; §§11.7–11.8 are DER-only.
				canonical := !strings.ContainsAny(value, ".,") && strings.HasSuffix(value, "Z") && (number == 23 && len(value) == 13 || number == 24 && len(value) == 15)
				if e = ValidateDEREncodedElement(wire); (e == nil) != canonical {
					t.Errorf("DER=%v canonical=%v", e, canonical)
				}
			})
		}
		invalid := []string{"", "x", "20260102030405Zjunk"}
		if number == 23 {
			invalid = append(invalid, "2613020304Z", "2602000304Z", "2602300304Z", "2601022400Z", "2601020360Z", "260102030460Z", "2601020304+2400", "2601020304+0060", "2601020304", "2601020304+01", "2601020304.5Z")
		} else {
			invalid = append(invalid, "20261302030405Z", "20260200030405Z", "20260230030405Z", "20260102240000Z", "20260102036000Z", "20260102030461Z", "20260102030405+24", "20260102030405+0060", "20260102030405.Z", "20260102030405,", "2026010203040Z")
		}
		for _, value := range invalid {
			wire := append([]byte{byte(number), byte(len(value))}, value...)
			assertRestrictedSentinels(t, ValidateBERElement(wire), true)
			_, _, e := decodeRestrictedTest(wire, number)
			assertRestrictedSentinels(t, e, true)
		}
	}
}

func TestRestrictedConstructedContents(t *testing.T) {
	for _, row := range []struct {
		wire, want string
		invalid    bool
	}{
		{"3e06040100040141", "A", false},
		{"3e80248004010000000401410000", "A", false},
		{"3c0c040100240704020001040141", "Ł", false},
		{"3e03040100", "", true}, {"3c03040100", "", true},
		{"3e060401d8040100", "", true},
	} {
		t.Run(row.wire, func(t *testing.T) {
			wire := structureWire(t, row.wire)
			err := ValidateBERElement(wire)
			assertRestrictedSentinels(t, err, row.invalid)
			got, _, err := DecodeString(wire, int(wire[0]&31))
			assertRestrictedSentinels(t, err, row.invalid)
			if !row.invalid && got != row.want {
				t.Errorf("got %q want %q", got, row.want)
			}
		})
	}
	for _, number := range []int{18, 19, 22, 26, 23, 24} {
		text := "A"
		if number == 18 {
			text = "1"
		}
		if number == 23 {
			text = "2601020304Z"
		}
		if number == 24 {
			text = "2026010203,25-05"
		}
		wire := []byte{byte(number) | 32, 128, 36, 128}
		for _, b := range []byte(text) {
			wire = append(wire, 4, 1, b)
		}
		wire = append(wire, 0, 0, 0, 0)
		assertRestrictedSentinels(t, ValidateBERElement(wire), false)
		got, _, err := decodeRestrictedTest(wire, number)
		assertRestrictedSentinels(t, err, false)
		if got != text {
			t.Errorf("got %q want %q", got, text)
		}
	}
}

func TestRestrictedContentsScanAllocations(t *testing.T) {
	for _, text := range []string{"1e020041", "1c040001f600", "120131", "130141", "160141", "1a0141", "3e06040100040141", "3e80248004010000000401410000"} {
		wire := structureWire(t, text)
		if err := ValidateBERElement(wire); err != nil {
			continue
		}
		if got := testing.AllocsPerRun(100, func() {
			if err := ValidateBERElement(wire); err != nil {
				panic(err)
			}
		}); got != 0 {
			t.Errorf("%s allocs=%v want 0", text, got)
		}
	}
	// Success-path growth: segmentation never needs a concatenation buffer.
	for _, size := range []int{1, 32, 1024, 16384} {
		leaves := bytes.Repeat([]byte{4, 1, 'A'}, size)
		wire := append([]byte{0x36}, EncodeLength(len(leaves))...)
		wire = append(wire, leaves...)
		if got := testing.AllocsPerRun(10, func() {
			if e := ValidateBERElement(wire); e != nil {
				panic(e)
			}
		}); got != 0 {
			t.Errorf("size=%d allocs=%v", size, got)
		}
	}
}

func TestRestrictedAlphabetToleranceSegments(t *testing.T) {
	for _, number := range []int{18, 19, 22, 26} {
		bad := byte(255)
		if number == 18 {
			bad = 'A'
		}
		if number == 19 {
			bad = '!'
		}
		wire := []byte{byte(number) | 32, 128, 4, 1, bad, 36, 128, 4, 1, '1', 4, 1, bad, 0, 0, 0, 0}
		var log ViolationLog
		opts, commit := StageDecodeReports(ChildDecodeOptions(ChildDecodeOptions([]DecodeOption{WithTolerance(&log)}, "message"), "text"))
		if err := ValidateBERElement(wire, opts...); err != nil {
			t.Fatal(err)
		}
		value, _, err := DecodeString(wire, number, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if value != string([]byte{bad, '1', bad}) {
			t.Errorf("octets changed")
		}
		commit(true)
		reports := log.Snapshot()
		if len(reports) != 2 {
			t.Fatalf("tag=%d duplicate reports: %+v", number, reports)
		}
		for i, offset := range []int{0, 2} {
			if reports[i].Path != "message.text" || reports[i].OctetOffset == nil || *reports[i].OctetOffset != offset {
				t.Errorf("tag=%d report %d: %+v", number, i, reports[i])
			}
		}
	}
}

func FuzzRestrictedStringContents(f *testing.F) {
	for which, contents := range [][]byte{{'1'}, {'A'}, {'a'}, {'~'}, {0, 0, 0, 65}, {0, 65}, []byte("2601020304Z"), []byte("2026010203,25-05")} {
		f.Add(byte(which), contents)
		f.Add(byte(which), []byte{255})
	}
	f.Fuzz(func(t *testing.T, which byte, contents []byte) {
		number := []int{18, 19, 22, 26, 28, 30, 23, 24}[int(which)%8]
		wire := append([]byte{byte(number)}, EncodeLength(len(contents))...)
		wire = append(wire, contents...)
		err := ValidateBERElement(wire)
		_, _, decodeErr := decodeRestrictedTest(wire, number)
		if (err == nil) != (decodeErr == nil) {
			t.Fatalf("tag=%d scan=%v typed=%v", number, err, decodeErr)
		}
		split := len(contents) / 2
		left := append([]byte{4}, EncodeLength(split)...)
		left = append(left, contents[:split]...)
		right := append([]byte{4}, EncodeLength(len(contents)-split)...)
		right = append(right, contents[split:]...)
		segments := append(left, right...)
		constructed := append([]byte{byte(number) | 32}, EncodeLength(len(segments))...)
		constructed = append(constructed, segments...)
		splitErr := ValidateBERElement(constructed)
		if (err == nil) != (splitErr == nil) {
			t.Fatalf("tag=%d primitive=%v split=%v", number, err, splitErr)
		}
	})
}

func TestRestrictedScalarEverySegmentBoundary(t *testing.T) {
	for _, row := range []struct {
		number   int
		contents []byte
		invalid  bool
	}{
		{30, []byte{0xd7, 0xff}, false}, {30, []byte{0xd8, 0}, true}, {30, []byte{0xe0, 0}, false},
		{28, []byte{0, 0x10, 0xff, 0xff}, false}, {28, []byte{0, 0x11, 0, 0}, true}, {28, []byte{0, 0, 0xd8, 0}, true},
	} {
		for split := 0; split <= len(row.contents); split++ {
			wire := []byte{byte(row.number) | 32, 128, 4, byte(split)}
			wire = append(wire, row.contents[:split]...)
			wire = append(wire, 36, 128, 4, byte(len(row.contents)-split))
			wire = append(wire, row.contents[split:]...)
			wire = append(wire, 0, 0, 0, 0)
			assertRestrictedSentinels(t, ValidateBERElement(wire), row.invalid)
			_, _, err := DecodeString(wire, row.number)
			assertRestrictedSentinels(t, err, row.invalid)
		}
	}
}

func TestRestrictedTimeScanAllocations(t *testing.T) {
	for _, row := range []struct {
		number int
		text   string
	}{
		{23, "2601020304Z"}, {24, "2026010203,25-05"},
		{24, "20260102030405." + strings.Repeat("3", 16384) + "Z"},
	} {
		primitive := append([]byte{byte(row.number)}, EncodeLength(len(row.text))...)
		primitive = append(primitive, row.text...)
		constructed := []byte{byte(row.number) | 32, 128}
		for _, b := range []byte(row.text) {
			constructed = append(constructed, 4, 1, b)
		}
		constructed = append(constructed, 0, 0)
		for _, wire := range [][]byte{primitive, constructed} {
			if got := testing.AllocsPerRun(10, func() {
				if err := ValidateBERElement(wire); err != nil {
					panic(err)
				}
			}); got != 0 {
				t.Errorf("time tag=%d allocs=%v", row.number, got)
			}
		}
	}
}

func TestRestrictedNamedEncoderAllocations(t *testing.T) {
	for _, encode := range []func(string) ([]byte, error){EncodeIA5String, EncodePrintableString} {
		if got := testing.AllocsPerRun(100, func() {
			if _, err := encode("123ABC"); err != nil {
				panic(err)
			}
		}); got != 1 {
			t.Errorf("named string encoder allocations=%v want 1", got)
		}
	}
}

func TestRestrictedTimeCalendarBoundaries(t *testing.T) {
	for _, text := range []string{"20000229000000Z", "20240229235959Z", "20260102030405.123Z"} {
		wire := append([]byte{24, byte(len(text))}, text...)
		assertRestrictedSentinels(t, ValidateBERElement(wire), false)
		assertRestrictedSentinels(t, ValidateDEREncodedElement(wire), false)
	}
	for _, text := range []string{"19000229000000Z", "20230229000000Z"} {
		wire := append([]byte{24, byte(len(text))}, text...)
		assertRestrictedSentinels(t, ValidateBERElement(wire), true)
	}
	for _, text := range []string{"0002290000Z", "991231235959Z"} {
		wire := append([]byte{23, byte(len(text))}, text...)
		assertRestrictedSentinels(t, ValidateBERElement(wire), false)
	}
	_, err := EncodeStringTagChecked(30, "\U0001f600")
	assertRestrictedSentinels(t, err, true)
}

func TestGeneratedOpenContentsWaitForTypedChecks(t *testing.T) {
	for _, bad := range [][]byte{{30, 1, 0}, {28, 3, 0, 0, 0}, {23, 1, 255}, {24, 1, 255}} {
		wire := append([]byte{0x30, byte(len(bad) + 3)}, bad...)
		wire = append(wire, 0x80, 1, 255)
		opts := TrackBERForm(nil)
		owned, err := OwnGeneratedBERInput(wire, opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = PrepareGeneratedBERInput(owned, opts); err != nil {
			t.Fatalf("open preflight hid a later typed check: %v", err)
		}
	}
}

func TestRestrictedContentsKeepLaterStructuralErrors(t *testing.T) {
	for _, bad := range [][]byte{{18, 1, 'A'}, {30, 1, 0}, {28, 3, 0, 0, 0}, {23, 1, 255}, {24, 1, 255}, {50, 3, 4, 1, 'A'}, {62, 3, 4, 1, 0}, {60, 3, 4, 1, 0}, {55, 3, 4, 1, 255}, {56, 3, 4, 1, 255}} {
		wire := append([]byte{0x30, byte(len(bad) + 3)}, bad...)
		wire = append(wire, 4, 2, 0)
		if err := ValidateBERElement(wire); !errors.Is(err, ErrTruncated) {
			t.Fatalf("bad=%x: %v", bad, err)
		}
	}
}
