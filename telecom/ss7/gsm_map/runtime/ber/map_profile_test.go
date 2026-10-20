// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/map_profile_test.go; SHA-256 3b4f516ebe0d9d51365e35c9dfaeaa012093fda5465eb8e026f4806799339ea7.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func profileDecode(t *testing.T, wire []byte, tolerant bool, visit func([]DecodeOption, []byte), extra ...DecodeOption) ([]Violation, error) {
	t.Helper()
	var log ViolationLog
	var opts []DecodeOption
	if tolerant {
		opts = []DecodeOption{WithTolerance(&log)}
	}
	opts = append(opts, extra...)
	opts, commit := StageDecodeReports(opts)
	opts = TrackMAPForm(opts)
	data, err := OwnGeneratedBERInput(wire, opts)
	if err != nil {
		return nil, err
	}
	data, opts, err = PrepareGeneratedBERInput(data, opts)
	if err != nil {
		return nil, err
	}
	opts = LocateDecodedElement(data, "MAP-Test.Root", opts)
	if visit != nil {
		visit(opts, data)
	}
	err = LocateDecodeError(nil, opts)
	commit(err == nil)
	return log.Snapshot(), err
}

func TestMAPProfileStringSegments(t *testing.T) {
	// The known string's fragments stay typed (X.690 (02/2021) §8.7.3).
	wire := structureWire(t, "240404810112")
	visit := func(opts []DecodeOption, data []byte) {
		if _, _, err := DecodeOctetString(data, opts...); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := profileDecode(t, wire, true, visit)
	if err != nil || len(rows) != 2 || rows[0].Constraint != "TS 29.002 §17.1.1: primitive-octet-string" || rows[1].Constraint != "TS 29.002 §17.1.1: short-length" || rows[1].Path != "child[0]" || rows[1].Offset == nil || *rows[1].Offset != 2 || !slices.Equal(rows[1].ChildIndexes, []int{0}) {
		t.Fatalf("records=%+v error=%v", rows, err)
	}
	rows, err = profileDecode(t, wire, true, visit, WithDiagnosticLimits(DiagnosticLimits{MaxRecords: 1}))
	if !errors.Is(err, ErrResourceLimit) || len(rows) != 0 {
		t.Fatalf("failed stage published records=%+v error=%v", rows, err)
	}
}

func TestMAPProfileEntryDepthGuard(t *testing.T) {
	form := &berFormState{mapSyntax: mapSyntaxProfile, mapDepth: math.MaxUint32}
	config := decodeConfig{form: form}
	beginMAPDecode(form, nil, nil, nil)
	if err := finishMAPDecode(nil, config); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("depth error=%v", err)
	}
}

func TestMAPProfileAllocationGrowth(t *testing.T) {
	measure := func(count int) uint64 {
		content := bytes.Repeat([]byte{4, 0x81, 1, 0x12}, count)
		wire, err := EncodeTLV(tag.Tag{Number: 16, Constructed: true}, content)
		if err != nil {
			t.Fatal(err)
		}
		_, tagLen, err := DecodeTag(wire)
		if err != nil {
			t.Fatal(err)
		}
		_, _, lenLen, err := DecodeLength(wire[tagLen:])
		if err != nil {
			t.Fatal(err)
		}
		start := tagLen + lenLen
		benchmark := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				rows, err := profileDecode(t, wire, true, func(opts []DecodeOption, data []byte) {
					for index := range count {
						offset := start + 4*index
						MarkPreflightElement(opts, index, data[offset:])
						if _, _, err := DecodeOctetString(data[offset:], opts...); err != nil {
							t.Fatal(err)
						}
					}
				})
				if err != nil || len(rows) != count {
					t.Fatalf("records=%d error=%v", len(rows), err)
				}
			}
		})
		return uint64(benchmark.AllocedBytesPerOp())
	}
	small, large := measure(64), measure(256)
	if small == 0 || large > 6*small {
		t.Fatalf("fourfold profile input grew allocation more than 6x: %d -> %d", small, large)
	}
}

func TestMAPProfileRules(t *testing.T) {
	for _, tc := range []struct{ name, hex string }{
		{"short-length", "04810112"},
		{"minimum-length-octets", "0482000112"},
		{"primitive-octet-string", "2403040112"},
		{"primitive-bit-string", "230403020080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := structureWire(t, tc.hex)
			_, err := profileDecode(t, wire, false, nil)
			var v *ValidationError
			ok := errors.As(err, &v)
			if !ok || !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("strict error=%T %v", err, err)
			}
			if v.Kind != ProtocolRule || v.Rule != (RuleRef{Document: "3GPP TS 29.002", Edition: "V19.1.0", Clause: "17.1.1"}) || v.Constraint != "TS 29.002 §17.1.1: "+tc.name || v.Source != "MAP-Test.Root" || v.Path != "" || v.Offset == nil || *v.Offset != 0 || len(v.ChildIndexes) != 0 {
				t.Fatalf("record=%+v", v)
			}
			records, err := profileDecode(t, wire, true, nil)
			if err != nil || len(records) != 1 || records[0].Constraint != v.Constraint {
				t.Fatalf("tolerant records=%+v error=%v", records, err)
			}
		})
	}
}

func TestMAPProfileBoundaries(t *testing.T) {
	// TS 29.002 V19.1.0 §17.1.1 explicitly allows empty constructors;
	// X.690 (02/2021) §8.1.3.6 permits constructed indefinite lengths.
	for _, wire := range [][]byte{{48, 0}, {49, 0}, {48, 128, 0, 0}, append([]byte{4, 127}, bytes.Repeat([]byte{1}, 127)...), append([]byte{4, 129, 128}, bytes.Repeat([]byte{1}, 128)...)} {
		for _, tolerant := range []bool{false, true} {
			if records, err := profileDecode(t, wire, tolerant, nil); err != nil || len(records) != 0 {
				t.Fatalf("accepted boundary: records=%+v error=%v", records, err)
			}
		}
	}
	// Decision B: a complete foreign encoding belongs to its own syntax,
	// including its header (X.690 (02/2021) §8.15).
	for _, tolerant := range []bool{false, true} {
		wire := structureWire(t, "3006248103040112")
		records, err := profileDecode(t, wire, tolerant, func(opts []DecodeOption, data []byte) {
			MarkPreflightTarget(opts, "extType", data[2:])
			MarkPreflightOpaque(opts, "extType", data[2:], len(data)-2)
		})
		if err != nil || len(records) != 0 {
			t.Fatalf("opaque records=%+v error=%v", records, err)
		}
		// An unclaimed extension is not a type defined by the compiled MAP schema.
		records, err = profileDecode(t, wire, tolerant, nil)
		if err != nil || len(records) != 0 {
			t.Fatalf("unknown addition records=%+v error=%v", records, err)
		}
	}
}

func TestMAPProfileNestedOnce(t *testing.T) {
	wire := structureWire(t, "300404810112")
	records, err := profileDecode(t, wire, true, func(opts []DecodeOption, data []byte) {
		MarkPreflightTarget(opts, "child", data[2:])
		child := []DecodeOption{ChildDecodeContext(opts, "child")}
		child = LocateDecodedElement(data[2:], "MAP-Other.Child", child)
		if err := LocateDecodeError(nil, child); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v error=%v", records, err)
	}
	v := records[0]
	if v.Path != "child" || v.Source != "MAP-Other.Child" || v.Offset == nil || *v.Offset != 2 || !slices.Equal(v.ChildIndexes, []int{0}) {
		t.Fatalf("record=%+v", v)
	}
}

func TestMAPProfileFinalEncode(t *testing.T) {
	wire := structureWire(t, "04810112")
	node := &ReplayNode{state: &ReplayState{mapViolations: true}}
	decode := func(data []byte, opts ...DecodeOption) (err error) {
		opts, commit := StageDecodeReports(opts)
		defer func() { commit(err == nil) }()
		opts = TrackMAPForm(opts)
		data, err = OwnGeneratedBERInput(data, opts)
		if err != nil {
			return err
		}
		data, opts, err = PrepareGeneratedBERInput(data, opts)
		if err != nil {
			return err
		}
		opts = LocateDecodedElement(data, "MAP-Test.Root", opts)
		return LocateDecodeError(nil, opts)
	}
	check := func(data []byte, opts []EncodeOption) error { return CheckMAPEncoded(data, node, opts, decode) }
	for _, check := range []func([]byte, []EncodeOption) error{check,
		func(data []byte, opts []EncodeOption) error { return CheckMAPEncoded(data, nil, opts, decode) },
		func(data []byte, opts []EncodeOption) error {
			return CheckMAPEncoded(data, &ReplayNode{state: &ReplayState{mapViolations: true}}, opts, decode)
		},
		func(data []byte, opts []EncodeOption) error { return CheckMAPEncodedElement(data, opts, decode) }} {
		err := check(wire, nil)
		var v *ValidationError
		ok := errors.As(err, &v)
		if !ok || !errors.Is(err, ErrInvalidValue) || v.Constraint != "TS 29.002 §17.1.1: short-length" || v.Source != "MAP-Test.Root" || v.Offset != nil || v.OctetOffset != nil || v.ChildIndexes != nil {
			t.Fatalf("strict final bytes: %T %v", err, err)
		}
		var log ViolationLog
		if err := check(wire, []EncodeOption{WithTolerance(&log)}); err != nil || len(log.Snapshot()) != 1 {
			t.Fatalf("tolerant final bytes: %v %+v", err, log.Snapshot())
		}
	}
	if err := CheckMAPEncoded(structureWire(t, "040112"), node, nil, func([]byte, ...DecodeOption) error { t.Fatal("canonical bytes needed a typed walk"); return nil }); err != nil {
		t.Fatal(err)
	}
	if !MAPEncodeBoundary(nil) || MAPEncodeBoundary([]EncodeOption{generatedEncodeMarker{}}) || MAPEncodeBoundary([]EncodeOption{replayModeOption{}}) {
		t.Fatal("nested final encode boundary")
	}
}

func TestMAPProfileFinalScan(t *testing.T) {
	for _, tc := range []struct {
		hex     string
		suspect bool
	}{
		{"3000", false}, {"30800000", false}, {"040112", false},
		{"04810112", true}, {"0482000112", true}, {"2403040112", true},
		{"230403020001", true}, {"a00403020001", true}, {"a000", true}, {"3005a000810100", true},
		{"1f", true}, {"0482", true}, {"0402ff", true}, {"04800000", true},
	} {
		if got := mapFormNeedsTypedCheck(structureWire(t, tc.hex)); got != tc.suspect {
			t.Errorf("final scan %s=%v, want %v", tc.hex, got, tc.suspect)
		}
	}
}

func TestMAPProfileExternalFields(t *testing.T) {
	// X.690 (02/2021) §8.18 keeps the identification and encoding-choice
	// headers typed; §8.15 leaves only a single-ASN1-type value opaque.
	for _, tc := range []struct {
		name, hex, rule string
		offset, child   int
	}{
		{"direct-reference", "28080681022a03810112", "short-length", 2, 0},
		{"encoding", "280906022a03a103040112", "primitive-octet-string", 6, 1},
		{"encoding", "280a06022a03a20403020001", "primitive-bit-string", 6, 1},
	} {
		rows, err := profileDecode(t, structureWire(t, tc.hex), true, func(opts []DecodeOption, data []byte) {
			if _, _, err := DecodeExternal(data, opts...); err != nil {
				t.Fatal(err)
			}
		})
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s records=%+v error=%v", tc.hex, rows, err)
		}
		v := rows[0]
		if v.Constraint != "TS 29.002 §17.1.1: "+tc.rule || v.Path != tc.name || v.Source != "MAP-Test.Root."+tc.name || v.Offset == nil || *v.Offset != tc.offset || !slices.Equal(v.ChildIndexes, []int{tc.child}) {
			t.Errorf("%s record=%+v", tc.hex, v)
		}
	}
}

func TestMAPProfileEncodeCoordinatesAndPositions(t *testing.T) {
	wire := structureWire(t, "30080481011204810112")
	decode := func(data []byte, opts ...DecodeOption) (err error) {
		opts, commit := StageDecodeReports(opts)
		defer func() { commit(err == nil) }()
		opts = TrackMAPForm(opts)
		data, err = OwnGeneratedBERInput(data, opts)
		if err != nil {
			return err
		}
		data, opts, err = PrepareGeneratedBERInput(data, opts)
		if err != nil {
			return err
		}
		opts = LocateDecodedElement(data, "MAP-Test.Root", opts)
		for index := range 2 {
			MarkPreflightElement(opts, index, data[2+4*index:])
			if _, _, err = DecodeOctetString(data[2+4*index:], opts...); err != nil {
				return err
			}
		}
		return LocateDecodeError(nil, opts)
	}
	err := CheckMAPEncoded(wire, nil, nil, decode)
	refusal, ok := err.(*ValidationError)
	if !ok || refusal.Offset != nil || refusal.OctetOffset != nil || refusal.ChildIndexes != nil || refusal.Path != "element[0]" {
		t.Fatalf("strict encode coordinates: %T %+v", err, err)
	}
	var log ViolationLog
	opts, commit := StageEncodeReports([]EncodeOption{WithTolerance(&log)})
	for range 2 {
		if err := CheckMAPEncoded(wire, nil, opts, decode); err != nil {
			t.Fatal(err)
		}
	}
	commit(true)
	rows := log.Snapshot()
	if len(rows) != 2 {
		t.Fatalf("distinct positions / repeated checks: %+v", rows)
	}
	for index, row := range rows {
		want := "element[0]"
		if index == 1 {
			want = "element[1]"
		}
		if row.Path != want || row.Offset != nil || row.OctetOffset != nil || row.ChildIndexes != nil {
			t.Fatalf("encode record %d: %+v", index, row)
		}
	}
}

func TestMAPProfileCleanReplayProof(t *testing.T) {
	wire := structureWire(t, "a30804031234560a0100")
	node := &ReplayNode{original: wire, state: &ReplayState{mapProfileChecked: true}}
	if err := CheckMAPEncoded(bytes.Clone(wire), node, nil, func([]byte, ...DecodeOption) error { t.Fatal("clean replay was decoded again"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := DeferMAPEncodeCheck(node, nil); err != nil {
		t.Fatal(err)
	}
	node.state.mapViolations = true
	if err := DeferMAPEncodeCheck(node, nil); !errors.Is(err, errMAPEncodeCheck) {
		t.Fatalf("retained finding=%v", err)
	}
	if err := DeferMAPEncodeCheck(node, []EncodeOption{replayModeOption{state: node.state, rebuildChildren: true}}); err != nil {
		t.Fatalf("edited root repair=%v", err)
	}
	options, retry := RetryMAPEncode(fmt.Errorf("child: %w", errMAPEncodeCheck), nil)
	if !retry {
		t.Fatal("missing root retry")
	}
	if err := DeferMAPEncodeCheck(node, options); err != nil {
		t.Fatal(err)
	}
}
func TestMAPProfileEncodeFiltersSourceRecords(t *testing.T) {
	var log ViolationLog
	err := CheckMAPEncoded(structureWire(t, "04810112"), nil, []EncodeOption{WithTolerance(&log)}, func(_ []byte, options ...DecodeOption) error {
		return CheckDecodedLength(DecodeRule(options, "MAP-Test.Leaf", RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "leaf", "SIZE (1)", 2)
	})
	if err != nil || len(log.Snapshot()) != 0 {
		t.Fatalf("non-profile findings republished: %v %+v", err, log.Snapshot())
	}
}
func TestMAPProfileRootSyntax(t *testing.T) {
	generic := TrackMAPSyntax(nil, false)
	generic = TrackMAPForm(generic)
	config, err := decodeOptions(generic)
	if err != nil || config.form.mapProfile() {
		t.Fatalf("import enabled generic root: %v", err)
	}
	profiled := TrackMAPForm(nil)
	profiled = TrackMAPSyntax(profiled, false)
	config, err = decodeOptions(profiled)
	if err != nil || !config.form.mapProfile() {
		t.Fatalf("import disabled MAP root: %v", err)
	}
}

func TestMAPProfileStandaloneScanRefuses(t *testing.T) {
	// TS 29.002 V19.1.0 §17.1.1 needs typed ownership to distinguish
	// MAP-defined elements from complete foreign encodings (X.690 §8.15).
	wire := structureWire(t, "318100")
	for _, options := range [][]DecodeOption{
		TrackMAPForm(nil),
		TrackMAPForm([]DecodeOption{WithTolerance(new(ViolationLog))}),
	} {
		err := ValidateBERElement(wire, options...)
		if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "generated MAP decoder") {
			t.Fatalf("standalone MAP scan error = %v, want explicit typed-entry refusal", err)
		}
	}
	if err := ValidateBERElement(wire); err != nil {
		t.Fatalf("generic BER scan = %v", err)
	}
}

func TestMAPProfileTrackingCaptureOptOutAllocations(t *testing.T) {
	options := []DecodeOption{WithoutReplayCapture()}
	base := testing.AllocsPerRun(100, func() { _ = TrackBERForm(options) })
	profile := testing.AllocsPerRun(100, func() { _ = TrackMAPSyntax(options, true) })
	if profile > base {
		t.Fatalf("profile tracking adds allocations: base=%g profile=%g", base, profile)
	}
}
