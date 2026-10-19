// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/utf8_location_test.go; SHA-256 633f81dd81b3a752bd5fb871255cb90dbd0c6e870ca88c3b4d94faa81617e045.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// Wide spans with sparse reports model every accepted generated MAP field path:
// each ancestor can revisit the same received value during reconciliation.
func TestUTF8ReportLookupDoesNotRescanAncestorSpans(t *testing.T) {
	const records = 128
	depth := DefaultDecodeLimits().MaxDepth
	measure := func(size int) int64 {
		value := bytes.Repeat([]byte{'a'}, size/records)
		value[0] = 0xff
		var content []byte
		for range records {
			content = append(content, mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, value))...)
		}
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagSequence, Constructed: true}, content))
		if err := ValidateBERElement(wire, WithTolerance(new(ViolationLog)), WithDecodeLimits(DecodeLimits{MaxWork: len(wire) - 1})); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("unaccounted preflight work: %v", err)
		}
		log := new(ViolationLog)
		options, finish := StageDecodeReports([]DecodeOption{WithTolerance(log), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: records})})
		config, err := decodeOptions(options)
		if err != nil {
			t.Fatal(err)
		}
		pending := config.violations
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatal(err)
		}
		if got := len(pending.records); got != records {
			t.Fatalf("preflight reports=%d want=%d", got, records)
		}
		if len(pending.locationOffsets) != records {
			t.Fatalf("indexed offsets=%d want=%d", len(pending.locationOffsets), records)
		}
		for i := range pending.records {
			pending.records[i].schemaDepth = depth + 1
		}
		origin := &decodeOrigin{root: wire}
		location := &decodeLocation{origin: origin, input: wire, source: "MAP.Message"}
		config.location = location
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for level := 0; level < depth; level++ {
					locateUTF8Reports(config, location, wire, "field", size-level, nil)
				}
			}
		})
		finish(true)
		return result.NsPerOp()
	}
	small, large := measure(64<<10), measure(1<<20)
	t.Logf("sparse lookup at %d nested paths: 64 KiB %d ns/op, 1 MiB %d ns/op", depth, small, large)
	if large > 4*small {
		t.Fatalf("sparse report lookup scales with span bytes: 64 KiB %d ns/op, 1 MiB %d ns/op", small, large)
	}
}

func TestUTF8ReportOffsetsStaySorted(t *testing.T) {
	var log ViolationLog
	for _, value := range []int{9, 3, 6, 3, 1} {
		offset, octet := value, value
		log.appendLocked(Violation{Offset: &offset, OctetOffset: &octet, Constraint: fmt.Sprint(value, len(log.records))})
	}
	if !slices.Equal(log.locationOffsets, []int{1, 3, 6, 9}) || len(log.locations[3]) != 2 {
		t.Fatalf("offset index=%v buckets=%v", log.locationOffsets, log.locations)
	}
	log.Reset()
	if len(log.locationOffsets) != 0 || len(log.locations) != 0 {
		t.Fatalf("reset retained offset index=%v", log.locationOffsets)
	}
}

func TestUTF8LocatedReports(t *testing.T) {
	wire := structureWire(t, "30070c02fffe0c01ff")
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 3})})
	options = LocateDecodedElement(wire, "Module.Message", options)
	if err := ValidateBERElement(wire, options...); err != nil {
		t.Fatal(err)
	}
	MarkPreflightTarget(options, "first", wire[2:])
	MarkPreflightOpaque(options, "first", wire[2:], 4)
	MarkPreflightTarget(options, "second", wire[6:])
	MarkPreflightOpaque(options, "second", wire[6:], 3)
	finish(true)
	records := reports.Snapshot()
	if len(records) != 3 {
		t.Fatalf("reports=%+v", records)
	}
	for i, r := range records {
		off, octet, path, idx := 2, i, "first", 0
		if i == 2 {
			off, octet, path, idx = 6, 0, "second", 1
		}
		if r.Offset == nil || *r.Offset != off || r.OctetOffset == nil || *r.OctetOffset != octet || r.Path != path || r.Source != "Module.Message."+path || !slices.Equal(r.ChildIndexes, []int{idx}) {
			t.Errorf("record %d: %+v", i, r)
		}
	}
}

func TestUTF8LocationReconciliationGrowth(t *testing.T) {
	for _, n := range []int{16, 64, 256, 1024} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			content := bytes.Repeat(structureWire(t, "0c02fffe"), n)
			wire := mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagSequence, Constructed: true}, content))
			var reports ViolationLog
			options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 2 * n})})
			options = LocateDecodedElement(wire, "Module.Message", options)
			if err := ValidateBERElement(wire, options...); err != nil {
				t.Fatal(err)
			}
			_, _, body, err := DecodeTLV(wire)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("field%d", i)
				MarkPreflightTarget(options, name, body[4*i:])
				if _, _, err := DecodeString(body[4*i:4*i+4], tag.TagUTF8String, ChildDecodeOptions(options, name)...); err != nil {
					t.Fatal(err)
				}
			}
			finish(true)
			got := reports.Snapshot()
			if len(got) != 2*n {
				t.Fatalf("records=%d want=%d", len(got), 2*n)
			}
			for i, r := range got {
				if r.Path != fmt.Sprintf("field%d", i/2) || r.Offset == nil || *r.Offset != len(wire)-len(body)+4*(i/2) || r.OctetOffset == nil || *r.OctetOffset != i%2 || !slices.Equal(r.ChildIndexes, []int{i / 2}) {
					t.Fatalf("record %d: %+v", i, r)
				}
			}
			// Each identifier is visited at most once by the resumable location pass.
			config, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			if visits := config.location.origin.ancestryVisits; visits > n+1 {
				t.Fatalf("ancestry visits=%d n=%d", visits, n)
			}
		})
	}
}

func TestUTF8LocatedBudgetFailureIsAtomic(t *testing.T) {
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 1})})
	wire := structureWire(t, "0c02fffe")
	options = LocateDecodedElement(wire, "Module.Text", options)
	err := ValidateBERElement(wire, options...)
	finish(err == nil)
	if !errors.Is(err, ErrResourceLimit) || len(reports.Snapshot()) != 0 {
		t.Fatalf("err=%v reports=%+v", err, reports.Snapshot())
	}
}

func TestUTF8NestedPreflightLocations(t *testing.T) {
	wire := structureWire(t, "3009300706022a030c01ff")
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 1})})
	if err := ValidateBERElement(wire, options...); err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(wire, "Module.Container", options)
	MarkPreflightTarget(options, "private", wire[2:])
	child := ChildDecodeOptions(options, "private")
	if err := ValidateBERElement(wire[2:], child...); err != nil {
		t.Fatal(err)
	}
	child = LocateDecodedElement(wire[2:], "Module.Private", child)
	MarkPreflightTarget(child, "open", wire[8:])
	MarkPreflightOpaque(child, "open", wire[8:], 3)
	finish(true)
	got := reports.Snapshot()
	if len(got) != 1 || got[0].Path != "private.open" || got[0].Source != "Module.Private.open" || got[0].Offset == nil || *got[0].Offset != 8 || !slices.Equal(got[0].ChildIndexes, []int{0, 1}) {
		t.Fatalf("records=%+v", got)
	}
}

func TestUTF8TypedImplicitLocation(t *testing.T) {
	wire := structureWire(t, "30068001018201ff")
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports)})
	options = LocateDecodedElement(wire, "Module.Message", options)
	MarkPreflightTarget(options, "text", wire[5:])
	if _, err := DecodeImplicitStringValue(tag.TagUTF8String, false, wire[7:], options...); err != nil {
		t.Fatal(err)
	}
	finish(true)
	got := reports.Snapshot()
	if len(got) != 1 || got[0].Path != "text" || got[0].Source != "Module.Message.text" || got[0].Offset == nil || *got[0].Offset != 5 || !slices.Equal(got[0].ChildIndexes, []int{1}) {
		t.Fatalf("records=%+v", got)
	}
}

func TestUTF8DistinctInputOrigins(t *testing.T) {
	first, second := structureWire(t, "0c01ff"), structureWire(t, "0c01ff")
	var reports ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&reports), WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 2})})
	for _, wire := range [][]byte{first, second} {
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatal(err)
		}
	}
	finish(true)
	if len(reports.Snapshot()) != 2 {
		t.Fatalf("different inputs collapsed: %+v", reports.Snapshot())
	}
}
