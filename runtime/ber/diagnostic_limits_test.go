package ber

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestBERDiagnosticDefaultHeapBound(t *testing.T) {
	for _, entry := range []string{"preflight", "typed", "implicit"} {
		t.Run(entry, func(t *testing.T) {
			for _, size := range []int{16 << 10, 64 << 10, 262 << 10} {
				wire := mustEncode(t)(EncodeUTF8String(string(bytes.Repeat([]byte{255}, size))))
				_, _, contents, err := DecodeTLV(wire)
				if err != nil {
					t.Fatal(err)
				}
				runtime.GC()
				var before, after, retained runtime.MemStats
				runtime.ReadMemStats(&before)
				var reports ViolationLog
				options, finish := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports)})
				switch entry {
				case "preflight":
					err = ValidateBERElement(wire, options...)
				case "typed":
					_, _, err = DecodeString(wire, tag.TagUTF8String, options...)
				case "implicit":
					_, err = DecodeImplicitStringValue(tag.TagUTF8String, false, contents, options...)
				}
				finish(err == nil)
				runtime.ReadMemStats(&after)
				if !errors.Is(err, ErrResourceLimit) {
					t.Errorf("%d bytes: expected fatal diagnostic limit, got %v", size, err)
				}
				if len(reports.Snapshot()) != 0 {
					t.Error("failed decode published reports")
				}
				allocated := after.TotalAlloc - before.TotalAlloc
				if allocated > 8<<20 {
					t.Errorf("%d bytes: allocated %d, limit 8 MiB", size, allocated)
				}
				runtime.GC()
				runtime.ReadMemStats(&retained)
				if retained.HeapAlloc > before.HeapAlloc+8<<20 {
					t.Errorf("%d bytes: retained heap exceeds 8 MiB growth bound", size)
				}
				t.Logf("%d malformed octets: allocated %d bytes, retained heap growth %d bytes", size, allocated, int64(retained.HeapAlloc)-int64(before.HeapAlloc))
				runtime.KeepAlive(options)
				runtime.KeepAlive(wire)
			}
		})
	}
}

func TestBERDiagnosticBudgetBoundaries(t *testing.T) {
	for _, limits := range []DiagnosticLimits{{MaxRecords: 2}, {MaxObservedBytes: 4}} {
		for _, constructed := range []bool{false, true} {
			for _, count := range []int{1, 2, 3} {
				wire := mustEncode(t)(EncodeUTF8String(string(bytes.Repeat([]byte{255}, count))))
				if constructed {
					fragments := mustEncode(t)(EncodeOctetString(wire[2:]))
					wire = mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String, Constructed: true}, fragments))
				}
				var reports ViolationLog
				options, finish := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports), WithDiagnosticLimits(limits)})
				options = TrackBERForm(options)
				err := ValidateBERElement(wire, options...)
				if err == nil {
					// Sharing one budget with a nested typed pass must not charge the same
					// octet twice, including provisional-to-field path upgrades.
					child, childFinish := StageDecodeReports(ChildDecodeOptions(options, "text"))
					var decoded string
					decoded, _, err = DecodeString(wire, tag.TagUTF8String, child...)
					childFinish(err == nil)
					if err == nil {
						canonical := mustEncode(t)(EncodeUTF8String(decoded))
						if !bytes.Equal(PreserveEncodedBER(canonical, wire, canonical, nil), wire) {
							t.Fatal("bounded reporting changed replay")
						}
					}
				}
				finish(err == nil)
				if count <= 2 {
					got := reports.Snapshot()
					if err != nil || len(got) != count {
						t.Fatalf("limits %+v count %d constructed %t: %v, %+v", limits, count, constructed, err, got)
					}
					for _, record := range got {
						if record.Path != "text" {
							t.Fatalf("typed path not upgraded: %+v", record)
						}
					}
				} else if !errors.Is(err, ErrResourceLimit) || errors.Is(err, ErrInvalidValue) || len(reports.Snapshot()) != 0 {
					t.Fatalf("limits %+v overflow: error %v, reports %+v", limits, err, reports.Snapshot())
				}
			}
		}
	}
}

func TestBERDiagnosticBudgetSharedAcrossFields(t *testing.T) {
	var reports ViolationLog
	option := WithConstraintTolerance(&reports)
	for range 2 {
		options, finish := StageDecodeReports([]DecodeOption{option, WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 2})})
		for _, name := range []string{"first", "second", "third"} {
			child, childFinish := StageDecodeReports(ChildDecodeOptions(options, name))
			err := CheckDecodedValue(child, "", "(0)", "1")
			childFinish(err == nil)
			if name == "third" {
				if !errors.Is(err, ErrResourceLimit) {
					t.Fatalf("field budget reset: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
		finish(false)
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed operations published reports")
	}
	// Separate direct calls each get the whole budget, even with a reused option.
	for range 2 {
		_, _, err := DecodeString([]byte{12, 2, 255, 254}, tag.TagUTF8String, option, WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 2}))
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(reports.Snapshot()) != 4 {
		t.Fatal("diagnostic budget leaked between direct operations")
	}
}

func TestBERObservedValuesAreBoundedAndIndependent(t *testing.T) {
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithConstraintTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxObservedBytes: 2 * MaxObservedValueBytes})})
	first := strings.Repeat("A", 4<<20) + "1"
	second := first[:len(first)-1] + "2"
	for _, observation := range []string{first, first, second} {
		if err := CheckDecodedValue(options, "text", "(0)", observation); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckDecodedValue(options, "other", "(0)", "x"); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("observed-byte overflow: %v", err)
	}
	finish(false)
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed byte-budget stage published reports")
	}
	config, err := decodeOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	got := config.violations.Snapshot()
	if len(got) != 2 {
		t.Fatalf("long values with distinct tails collapsed: %+v", got)
	}
	for _, record := range got {
		if len(record.ObservedValue) != MaxObservedValueBytes || record.ObservedValueLength != len(first) {
			t.Fatalf("uncapped observation: length %d, true length %d", len(record.ObservedValue), record.ObservedValueLength)
		}
	}
}

func TestBERDiagnosticLimitDefaultsAndValidation(t *testing.T) {
	for _, limits := range []DiagnosticLimits{{}, {MaxRecords: 1}, {MaxObservedBytes: 1}, {MaxRecords: 1, MaxObservedBytes: 1}} {
		config, err := decodeOptions([]DecodeOption{WithDiagnosticLimits(limits)})
		if err != nil {
			t.Fatal(err)
		}
		want := DefaultDiagnosticLimits()
		if limits.MaxRecords != 0 {
			want.MaxRecords = limits.MaxRecords
		}
		if limits.MaxObservedBytes != 0 {
			want.MaxObservedBytes = limits.MaxObservedBytes
		}
		if config.diagnostics != want {
			t.Fatalf("zero default override: %+v want %+v", config.diagnostics, want)
		}
	}
}
