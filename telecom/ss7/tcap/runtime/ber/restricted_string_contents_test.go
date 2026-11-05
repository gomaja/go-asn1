// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/restricted_string_contents_test.go; SHA-256 da6b5974c323db4eb757875f45a27e02e53598b2459739d5bf71922bad095f4f.
package ber

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func assertRestrictedSentinels(t *testing.T, err error, invalid bool) {
	t.Helper()
	for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit} {
		if got, want := errors.Is(err, sentinel), invalid && sentinel == ErrInvalidValue; got != want {
			t.Errorf("error %v: errors.Is(%v)=%v want %v", err, sentinel, got, want)
		}
	}
	if !invalid && err != nil {
		t.Errorf("unexpected error: %v", err)
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
		opts = TrackBERForm(opts)
		owned, err := OwnGeneratedBERInput(wire, opts)
		if err != nil {
			t.Fatal(err)
		}
		wire, opts, err = PrepareGeneratedBERInput(owned, opts)
		if err != nil {
			t.Fatal(err)
		}
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
		if !BERNeedsPreservation(opts) {
			t.Error("received form not retained")
		}
	}
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

func TestRestrictedContentsKeepLaterStructuralErrors(t *testing.T) {
	for _, bad := range [][]byte{{18, 1, 'A'}, {30, 1, 0}, {28, 3, 0, 0, 0}, {23, 1, 255}, {24, 1, 255}, {50, 3, 4, 1, 'A'}, {62, 3, 4, 1, 0}, {60, 3, 4, 1, 0}, {55, 3, 4, 1, 255}, {56, 3, 4, 1, 255}} {
		wire := append([]byte{0x30, byte(len(bad) + 3)}, bad...)
		wire = append(wire, 4, 2, 0)
		if err := ValidateBERElement(wire); !errors.Is(err, ErrTruncated) {
			t.Fatalf("bad=%x: %v", bad, err)
		}
	}
}
