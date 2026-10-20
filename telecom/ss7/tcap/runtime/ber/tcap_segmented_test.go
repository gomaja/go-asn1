// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_segmented_test.go; SHA-256 9b3c9b6a277031d5e339f51916a75cafb2bd0e4698b42beb59159d027d8b4fc6.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"reflect"
	"strings"
	"testing"
)

// Q.773 (06/1997) §§3.2, 4.1.1, 4.2.3; X.690 (02/2021)
// §§8.6.4, 8.7.3, 8.18.10–8.18.11: audit the APDU after reassembly.
func TestTCAPSegmentedDialogueProfile(t *testing.T) {
	for _, row := range []struct {
		name, wire    string
		count, offset int
	}{
		{"primitive", "62274801016b22282006070011860501010181156013a00403020780a10b06092b0601040183b20302", 1, 22},
		{"octets", "622b4801016b262824060700118605010101a119040160041413a00403020780a10b06092b0601040183b20302", 2, 26},
		{"nested-octets", "622d4801016b282826060700118605010101a11b0401602416041413a00403020780a10b06092b0601040183b20302", 3, 28},
		{"bits", "622d4801016b282826060700118605010101a21b0302006003150013a00403020780a10b06092b0601040183b20302", 2, 28},
		{"nested-bits", "622f4801016b2a2828060700118605010101a21d03020060231703150013a00403020780a10b06092b0601040183b20302", 3, 30},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, _ := hex.DecodeString(row.wire)
			var log ViolationLog
			opts := TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "TCMessage")
			if err := ValidateBERElement(wire, opts...); err != nil {
				t.Fatal(err)
			}
			reports := log.Snapshot()
			if len(reports) != row.count {
				t.Fatalf("reports = %+v, want %d", reports, row.count)
			}
			v := reports[len(reports)-1]
			if v.Offset == nil || *v.Offset != row.offset || v.Path != "begin.dialoguePortion.dialogue.dialogueRequest.protocol-version" || !strings.HasSuffix(v.Constraint, "primitive-bit-string") {
				t.Fatalf("APDU location = %+v", v)
			}
			// Logical ancestry below the encoding choice, independent of segmentation.
			if !reflect.DeepEqual(v.ChildIndexes, []int{1, 0, 1, 0, 0}) {
				t.Fatalf("APDU indexes = %v", v.ChildIndexes)
			}
			if err := ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...); err == nil {
				t.Fatal("strict accepted")
			}
		})
	}
}

// Segment count, data size and nesting share the public preflight budgets.
// X.690 (02/2021) §§8.6.4, 8.7.3; these are operational limits, not BER rules.
func TestTCAPSegmentedDialogueBounds(t *testing.T) {
	wrap := func(id byte, body []byte) []byte {
		out, err := EncodeTLV(tag.Tag{Class: tag.Class(id >> 6), Constructed: id&32 != 0, Number: int(id & 31)}, body)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, bit := range []bool{false, true} {
		for _, count := range []int{16, 256, 4096} {
			t.Run(fmt.Sprintf("bits=%t/%d", bit, count), func(t *testing.T) {
				var segments []byte
				for range count {
					if bit {
						segments = append(segments, 3, 1, 0)
					} else {
						segments = append(segments, 4, 0)
					}
				}
				apdu, _ := hex.DecodeString("6013a00403020780a10b06092b0601040183b20302")
				id := byte(4)
				choice := byte(0xa1)
				if bit {
					id = 3
					choice = 0xa2
					apdu = append([]byte{0}, apdu...)
				}
				segments = append(segments, wrap(id, apdu)...)
				wire := wrap(0x62, append([]byte{0x48, 1, 1}, wrap(0x6b, wrap(0x28, append([]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, wrap(choice, segments)...)))...))
				var log ViolationLog
				opts := TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "TCMessage")
				if err := ValidateBERElement(wire, opts...); err != nil {
					t.Fatal(err)
				}
				if len(log.Snapshot()) != 2 {
					t.Fatalf("reports: %+v", log.Snapshot())
				}
				for _, limit := range []DecodeLimits{{MaxWork: len(wire)}, {MaxElements: count + 9}, {MaxDepth: 5}} {
					var rejected ViolationLog
					o := TrackTCAPForm([]DecodeOption{WithTolerance(&rejected), WithDecodeLimits(limit)}, "TCMessage")
					if err := ValidateBERElement(wire, o...); !errors.Is(err, ErrResourceLimit) {
						t.Fatalf("limit %+v: %v", limit, err)
					}
				}
				// The work counter includes the physical wire plus the APDU's second scan.
				config, _ := decodeOptions(opts)
				scan := &dialogueScanOption{config: config}
				if err := ValidateBERElement(wire, scan); err != nil {
					t.Fatal(err)
				}
				if scan.work != len(wire)+21 || scan.elements != count+12 {
					t.Fatalf("work/elements = %d/%d, wire=%d count=%d", scan.work, scan.elements, len(wire), count)
				}
			})
		}
	}

	// Port the oracle's one-octet leaf shapes, and chains of nested segments.
	// With profile reports suppressed, exact scanner work must equal wire size.
	for _, bit := range []bool{false, true} {
		for _, count := range []int{16, 256, 4096} {
			for _, nested := range []bool{false, true} {
				leaf := []byte{4, 1, 'x'}
				id := byte(0x24)
				if bit {
					leaf = []byte{3, 2, 0, 'x'}
					id = 0x23
				}
				wire := wrap(id, bytes.Repeat(leaf, count))
				want := bytes.Repeat([]byte{'x'}, count)
				if nested {
					wire = leaf
					for range count {
						wire = append(append([]byte{id, 0x80}, wire...), 0, 0)
					}
					want = []byte{'x'}
				}
				segments := new(dialogueSegments)
				cfg := decodeConfig{limits: DecodeLimits{MaxWork: len(wire), MaxElements: count + 1, MaxDepth: count + 1}, diagnostics: DefaultDiagnosticLimits(), collectPositionsOnly: true}
				scan := &dialogueScanOption{config: cfg, collect: segments}
				if err := ValidateBERElement(wire, scan); err != nil {
					t.Fatalf("bits=%t count=%d nested=%t: %v", bit, count, nested, err)
				}
				if !bytes.Equal(segments.contents, want) || scan.work != len(wire) || scan.elements != count+1 || len(segments.offsets) != len(want) {
					t.Fatalf("nonlinear or incomplete reassembly: bytes=%d work=%d elements=%d", len(segments.contents), scan.work, scan.elements)
				}
				if cap(segments.contents) > 2*len(want)+8 || cap(segments.offsets) > 2*len(want)+8 {
					t.Fatal("unbounded reassembly capacity")
				}
			}
		}
	}
}

// A violating identifier or its length may cross a segment boundary. Its
// first octet still identifies the report (Q.773 §4.1.1; X.690 §§8.6.4, 8.7.3).
func TestTCAPSegmentedDialogueEveryBoundary(t *testing.T) {
	wrap := func(id byte, body []byte, indefinite bool) []byte {
		if indefinite {
			return append(append([]byte{id, 0x80}, body...), 0, 0)
		}
		out, err := EncodeTLV(tag.Tag{Class: tag.Class(id >> 6), Constructed: id&32 != 0, Number: int(id & 31)}, body)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, long := range []bool{false, true} {
		protocol := []byte{0xa0, 4, 3, 2, 7, 0x80}
		if long {
			protocol = []byte{0xa0, 0x81, 4, 3, 2, 7, 0x80}
		}
		acn, _ := hex.DecodeString("a10b06092b0601040183b20302")
		apdu := wrap(0x60, append(protocol, acn...), false)
		for _, bit := range []bool{false, true} {
			for _, nested := range []bool{false, true} {
				for _, indefinite := range []bool{false, true} {
					for cut := 1; cut < len(apdu); cut++ {
						id, choice := byte(4), byte(0xa1)
						leaf := func(payload []byte) []byte { return wrap(id, payload, false) }
						if bit {
							id = 3
							choice = 0xa2
							leaf = func(payload []byte) []byte { return wrap(id, append([]byte{0}, payload...), false) }
						}
						first, last := leaf(apdu[:cut]), leaf(apdu[cut:])
						if nested {
							last = wrap(id|0x20, last, indefinite)
						}
						encoded := wrap(choice, append(first, last...), indefinite)
						ext := wrap(0x28, append([]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, encoded...), false)
						wire := wrap(0x62, append([]byte{0x48, 1, 1}, wrap(0x6b, ext, false)...), false)
						var reports ViolationLog
						if err := ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&reports)}, "TCMessage")...); err != nil {
							t.Fatal(err)
						}
						rows := reports.Snapshot()
						want := 2
						if nested {
							want++
						}
						if long {
							want++
						}
						if len(rows) != want {
							t.Fatalf("cut=%d bits=%t nested=%t indefinite=%t long=%t: %+v", cut, bit, nested, indefinite, long, rows)
						}
						offset := bytes.IndexByte(wire, 0xa0)
						for _, v := range rows[len(rows)-1-btoi(long):] {
							if v.Offset == nil || *v.Offset != offset || v.Path != "begin.dialoguePortion.dialogue.dialogueRequest.protocol-version" || !reflect.DeepEqual(v.ChildIndexes, []int{1, 0, 1, 0, 0}) {
								t.Fatalf("split identifier location: %+v wire=%x", v, wire)
							}
						}
						var strict *ValidationError
						if err := ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...); !errors.As(err, &strict) || strict.Offset == nil || *strict.Offset != 18 {
							t.Fatalf("strict header: %v", err)
						}
					}
				}
			}
		}
	}
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}

// X.690 (02/2021) §8.6.2.2 requires the unused-bit-count octet even in
// an empty BIT STRING leaf. Reject it before advancing the mapped data start.
func TestTCAPSegmentedDialogueEmptyBitLeaf(t *testing.T) {
	// A nonempty constructed arbitrary value containing a zero-content leaf.
	wire, _ := hex.DecodeString("62164801016b11280f060700118605010101a20403000300")
	var reports ViolationLog
	err := ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&reports)}, "TCMessage")...)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("missing bit count: %v", err)
	}
}

// A reconstructed IMPLICIT identifier may have a shorter header than its
// received element. Map its content through the received header in logical
// APDU coordinates before looking up physical positions (X.690 §8.1.3).
func TestTCAPSegmentedReconstructedHeaderLocations(t *testing.T) {
	root := []byte{0xa1, 0x81, 3, 2, 1, 1}
	segments := &dialogueSegments{contents: root, offsets: []int{20, 24, 28, 32, 36, 40}}
	copied := []byte{0x30, 3, 2, 1, 1}
	location := &decodeLocation{origin: &decodeOrigin{root: root, search: positionSearch{segments: segments}}, input: copied, offset: 20}
	for offset, want := range []int{20, 24, 32, 36, 40} {
		got, ok := location.wireOffset(copied[offset:])
		if !ok || got != want {
			t.Fatalf("offset=%d got=%d/%t want=%d", offset, got, ok, want)
		}
	}
	// A hole between string leaves is not an APDU position. Never let an
	// unsuccessful inverse mapping attach a report to the following element.
	location.offset = 25
	if got, ok := location.wireOffset(copied[2:]); ok {
		t.Fatalf("unmapped received position returned %d", got)
	}
}

func TestTCAPSegmentedNestedScanOwnership(t *testing.T) {
	// The public outer scan owns the reports and work; nested typed preflight
	// must not rescan a segmented APDU (Q.773 §4.1.1).
	wire, _ := hex.DecodeString("622b4801016b262824060700118605010101a119040160041413a00403020780a10b06092b0601040183b20302")
	var log ViolationLog
	options := TrackTCAPForm([]DecodeOption{WithTolerance(&log), WithDecodeLimits(DecodeLimits{MaxWork: len(wire)})}, "Begin")
	options = TrackTCAPForm(options, "TCMessage")
	if err := ValidateBERElement(wire, options...); err != nil {
		t.Fatal(err)
	}
	if got := log.Snapshot(); len(got) != 0 {
		t.Fatalf("nested scan published %+v", got)
	}
}

func TestTCAPSegmentedAuditWithinLocatedInput(t *testing.T) {
	// Audit a subslice of a public input. Reassembled offsets are relative to
	// that subslice until translated by the caller's location (Q.773 §4.1.1).
	wire, _ := hex.DecodeString("622b4801016b262824060700118605010101a119040160041413a00403020780a10b06092b0601040183b20302")
	envelope := append([]byte{0x30, byte(len(wire))}, wire...)
	var log ViolationLog
	options := LocateDecodedElement(envelope, "envelope", []DecodeOption{WithTolerance(&log)})
	options = LocateDecodedElement(envelope[2:], "TCMessage", options)
	options = TrackTCAPForm(options, "TCMessage")
	if err := ValidateBERElement(envelope[2:], options...); err != nil {
		t.Fatal(err)
	}
	reports := log.Snapshot()
	if len(reports) != 2 || reports[1].Offset == nil || *reports[1].Offset != 28 {
		t.Fatalf("nested audit reports=%+v", reports)
	}
}

func TestTCAPSegmentedDialogueFinalUnusedBits(t *testing.T) {
	// X.690 §§8.6.4, 8.18.11: a known BER APDU needs integral octets;
	// refuse at the located string segment before attempting the APDU scan.
	wire, _ := hex.DecodeString("622d4801016b282826060700118605010101a21b0306006013a00403031104020780a10b06092b0601040183b20302")
	for _, indefinite := range []bool{false, true} {
		input := bytes.Clone(wire)
		if indefinite {
			input[19] = 0x80
			input = append(input, 0, 0)
			input[1] += 2
			input[6] += 2
			input[8] += 2
		}
		var log ViolationLog
		err := ValidateBERElement(input, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, "TCMessage")...)
		var element *ElementError
		if !errors.As(err, &element) || !strings.Contains(err.Error(), "known dialogue requires integral octets") || !reflect.DeepEqual(element.ChildIndexes(), []int{1, 0, 1, 2}) {
			t.Fatalf("indefinite=%t preflight=%v", indefinite, err)
		}
	}
}

// The failure-path repair index walks each reassembled octet and report once,
// then serves every typed node from the same index (X.690 §§8.6.4, 8.7.3).
func TestTCAPSegmentedReplayIndexGrowth(t *testing.T) {
	for _, count := range []int{16, 256, 4096} {
		segments := &dialogueSegments{offsets: make([]int, count)}
		wire := &replayProfileIndex{offsets: []int{1}}
		for i := range count {
			segments.offsets[i] = 20 + 3*i
			wire.offsets = append(wire.offsets, 20+3*i, 21+3*i)
		}
		got := segments.replayIndex(wire)
		if len(got.offsets) != count || cap(got.offsets) > 2*count+8 {
			t.Fatalf("count=%d size=%d capacity=%d", count, len(got.offsets), cap(got.offsets))
		}
		for i, offset := range got.offsets {
			if offset != i {
				t.Fatalf("logical %d=%d", i, offset)
			}
		}
		if segments.replayIndex(wire) != got {
			t.Fatal("rebuilt repair index")
		}
	}
}
