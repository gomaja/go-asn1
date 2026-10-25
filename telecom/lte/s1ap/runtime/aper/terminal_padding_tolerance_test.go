// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/terminal_padding_tolerance_test.go; SHA-256 500cf4b4cab4f472f0095e3b9068bb962f5082ef92bbc2aba42bf9438dfe609a.
package aper

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTerminalPaddingStrictLocation(t *testing.T) {
	for _, opts := range [][]DecodeOption{nil, {WithReceiverMode()}} {
		state := ApplyDecodeOptions(opts...)
		bb := NewBitBufferFromBytes([]byte{1})
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBits(7); err != nil {
			t.Fatal(err)
		}
		_, err := CaptureFinalBits(bb, "Synthetic")
		var located *DecodeError
		if !errors.As(err, &located) || located.Location.Path != "Synthetic" || strings.Contains(err.Error(), "at :") {
			t.Fatalf("unlocated refusal: %v / %+v", err, located)
		}
		report, err := FinishDecode(state, err)
		if !errors.Is(err, ErrSyntax) || len(report.Deviations) != 1 || len(report.Observations) != 0 || report.Deviations[0].Location.Path != "Synthetic" {
			t.Fatalf("strict report=%+v error=%v", report, err)
		}
	}
}

// X.691 (02/2021) §§11.1.4 and 11.2.1: ordinary terminal bits and the
// replacement empty octet are separate observations of the same opt-in policy.
func TestTerminalPaddingToleranceAtEveryWidth(t *testing.T) {
	for used := 0; used < 8; used++ {
		for _, paddingValue := range []uint8{1, uint8((1 << uint(8-used)) - 1)} {
			for _, open := range []bool{false, true} {
				for _, receiver := range []bool{false, true} {
					options := []DecodeOption{WithNonzeroTerminalPadding()}
					if receiver {
						options = append(options, WithReceiverMode())
					}
					state := ApplyDecodeOptions(options...)
					bb := NewBitBufferFromBytes([]byte{paddingValue})
					if err := bb.SetDecodeOptionsAligned(state); err != nil {
						t.Fatal(err)
					}
					if _, err := bb.ReadBits(used); err != nil {
						t.Fatal(err)
					}
					var err error
					if open {
						_, err = CaptureOpenTypePadding(bb)
					} else {
						_, err = CaptureFinalBits(bb, "Synthetic")
					}
					if err != nil {
						t.Fatalf("used=%d open=%t: %v", used, open, err)
					}
					report, err := FinishDecode(state, nil)
					if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
						t.Fatalf("report=%+v error=%v", report, err)
					}
					kind, clause, path := NonzeroTerminalPadding, "§11.1.4", Path("Synthetic")
					if used == 0 {
						kind = NonzeroEmptyEncoding
					}
					if open {
						clause = "§11.2.1"
						path = "open type"
					}
					want := Observation{Kind: kind, PaddingBits: paddingValue, PaddingCount: uint8(8 - used), Rule: SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: clause}, Location: Location{Path: path, HasWireLocation: true, Spans: []BitSpan{{Start: uint64(used), End: 8}}}}
					if !reflect.DeepEqual(report.Observations[0], want) {
						t.Fatalf("used=%d open=%t: got=%+v want=%+v", used, open, report.Observations[0], want)
					}
				}
			}
		}
	}
}

func TestTerminalPaddingToleranceDoesNotAcceptOtherErrors(t *testing.T) {
	for _, tc := range []struct {
		wire []byte
		used int
		want error
	}{
		{nil, 0, ErrTruncated}, {[]byte{0, 0}, 1, ErrExtraData}, {[]byte{0, 0}, 8, ErrExtraData},
	} {
		state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
		bb := NewBitBufferFromBytes(tc.wire)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBits(tc.used); err != nil {
			t.Fatal(err)
		}
		_, err := CaptureFinalBits(bb, "Synthetic")
		report, err := FinishDecode(state, err)
		if !errors.Is(err, tc.want) || len(report.Observations) != 0 {
			t.Fatalf("wire=%x used=%d report=%+v err=%v", tc.wire, tc.used, report, err)
		}
	}
	state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
	bb := NewBitBufferFromBytes([]byte{1})
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBit(); err != nil {
		t.Fatal(err)
	}
	if err := bb.AlignToOctetRead(); !errors.Is(err, ErrSyntax) {
		t.Fatalf("internal alignment tolerated: %v", err)
	}
}

func TestTerminalPaddingNestedLocationsAndReportLimit(t *testing.T) {
	for _, maximum := range []uint64{1, 2, 3} {
		state := ApplyDecodeOptions(WithNonzeroTerminalPadding(), WithLimits(Limits{MaxReports: maximum}))
		writer := NewBitBuffer()
		for range 2 {
			if err := EncodeOpenTypeAligned(writer, []byte{1}); err != nil {
				t.Fatal(err)
			}
		}
		bb := NewBitBufferFromBytes(writer.CompleteBytes())
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		var failure error
		for index := range 2 {
			mark := bb.EnterComponent("Values")
			item := bb.EnterIndex(int64(index))
			raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
			if err != nil {
				t.Fatal(err)
			}
			child := raw.ChildDecodeBuffer()
			if _, err := child.ReadBits(7); err != nil {
				t.Fatal(err)
			}
			_, failure = CaptureFinalBits(child, "Boolean")
			bb.LeaveComponent(item)
			bb.LeaveComponent(mark)
			if failure != nil {
				break
			}
		}
		if failure == nil {
			_, failure = CaptureFinalBits(bb, "Synthetic")
		}
		report, failure := FinishDecode(state, failure)
		if maximum == 1 {
			if !errors.Is(failure, ErrLimit) || len(report.Observations) != 1 {
				t.Fatalf("report ceiling bypassed: %+v %v", report, failure)
			}
			continue
		}
		if failure != nil || len(report.Observations) != 2 {
			t.Fatalf("nested reports: %+v %v", report, failure)
		}
		for i, observation := range report.Observations {
			want := Location{Path: Path([]string{"Synthetic.Values[0]", "Synthetic.Values[1]"}[i]), HasWireLocation: true, Spans: []BitSpan{{Start: uint64(15 + 16*i), End: uint64(16 + 16*i)}}}
			if !reflect.DeepEqual(observation.Location, want) || observation.Kind != NonzeroTerminalPadding || observation.PaddingBits != 1 || observation.PaddingCount != 1 || observation.Rule.Clause != "§11.2.1" {
				t.Fatalf("observation[%d]=%+v want location=%+v", i, observation, want)
			}
		}
	}
}

func TestTerminalPaddingOptionsAreIndependent(t *testing.T) {
	options := []DecodeOption{WithReceiverMode(), WithNonzeroTerminalPadding()}
	for run := range 3 {
		state := ApplyDecodeOptions(options...)
		bb := NewBitBufferFromBytes([]byte{0x80})
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		_, err := CaptureFinalBits(bb, "Empty")
		report, err := FinishDecode(state, err)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].PaddingBits != 0x80 || report.Observations[0].PaddingCount != 8 {
			t.Fatalf("call %d: %+v %v", run, report, err)
		}
		strict := ApplyDecodeOptions(WithReceiverMode())
		reader := NewBitBufferFromBytes([]byte{0x80})
		if err := reader.SetDecodeOptionsAligned(strict); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureFinalBits(reader, "Empty"); !errors.Is(err, ErrSyntax) {
			t.Fatalf("tolerance leaked: %v", err)
		}
	}
}

func TestTerminalPaddingFragmentedLocation(t *testing.T) {
	state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
	contents := make([]byte, 16385)
	contents[len(contents)-1] = 1
	writer := NewBitBuffer()
	if err := EncodeOpenTypeAligned(writer, contents); err != nil {
		t.Fatal(err)
	}
	wire := writer.CompleteBytes()
	parent := NewBitBufferFromBytes(wire)
	if err := parent.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	child := raw.ChildDecodeBuffer()
	if _, err := child.ReadBytes(16384); err != nil {
		t.Fatal(err)
	}
	if _, err := child.ReadBit(); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(child, "Fragmented"); err != nil {
		t.Fatal(err)
	}
	report, err := FinishDecode(state, nil)
	if err != nil || len(report.Observations) != 1 {
		t.Fatalf("fragmented report=%+v %v", report, err)
	}
	observation := report.Observations[0]
	if !reflect.DeepEqual(observation.Location.Spans, []BitSpan{{Start: uint64(len(wire)-1)*8 + 1, End: uint64(len(wire)) * 8}}) || observation.PaddingCount != 7 || observation.PaddingBits != 1 || observation.Rule.Clause != "§11.2.1" {
		t.Fatalf("fragmented observation=%+v", observation)
	}
}

func TestTerminalPaddingLinearBudgets(t *testing.T) {
	for _, count := range []int{16, 32, 64} {
		wire := make([]byte, count*2)
		for i := 0; i < count; i++ {
			wire[i*2] = 1
			wire[i*2+1] = 1
		}
		decode := func(maximum uint64) (DecodeUsage, error) {
			state := ApplyDecodeOptions(WithNonzeroTerminalPadding(), WithLimits(Limits{MaxAllocatedBytes: maximum}))
			reader := NewBitBufferFromBytes(wire)
			if err := reader.SetDecodeOptionsAligned(state); err != nil {
				return state.Usage(), err
			}
			for i := 0; i < count; i++ {
				mark := reader.EnterComponent("Values")
				index := reader.EnterIndex(int64(i))
				raw, err := DecodeOpaqueOpenTypeAligned(reader, UnknownSelector, SourceRule{})
				if err != nil {
					return state.Usage(), err
				}
				child := raw.ChildDecodeBuffer()
				if _, err := child.ReadBits(7); err != nil {
					return state.Usage(), err
				}
				if _, err := CaptureFinalBits(child, "Boolean"); err != nil {
					return state.Usage(), err
				}
				reader.LeaveComponent(index)
				reader.LeaveComponent(mark)
			}
			if _, err := CaptureFinalBits(reader, "Synthetic"); err != nil {
				return state.Usage(), err
			}
			report, err := FinishDecode(state, nil)
			if err == nil && len(report.Observations) != count {
				t.Fatalf("count=%d report=%+v", count, report)
			}
			return state.Usage(), err
		}
		usage, err := decode(0)
		if err != nil {
			t.Fatal(err)
		}
		if usage.Reports != uint64(count) || usage.AllocatedBytes > operationMetadataBytes+uint64(count)*4096 || usage.Work > operationMetadataBytes+uint64(count)*4096 {
			t.Fatalf("nonlinear resource growth: count=%d usage=%+v", count, usage)
		}
		for _, ceiling := range []uint64{usage.AllocatedBytes - 1, usage.AllocatedBytes, usage.AllocatedBytes + 1} {
			_, err := decode(ceiling)
			if ceiling < usage.AllocatedBytes {
				if !errors.Is(err, ErrLimit) {
					t.Fatalf("allocation ceiling=%d usage=%d error=%v", ceiling, usage.AllocatedBytes, err)
				}
			} else if err != nil {
				t.Fatalf("exact allocation ceiling=%d error=%v", ceiling, err)
			}
		}
	}
}

func TestTerminalPaddingEmptyReplay(t *testing.T) {
	received := []byte{0x80}
	owned, state := StartDecode(received, WithNonzeroTerminalPadding())
	reader := NewCompleteDecodeBuffer(owned, state)
	if err := reader.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(reader, "Empty"); err != nil {
		t.Fatal(err)
	}
	report, err := FinishDecode(state, nil)
	if err != nil || len(report.Observations) != 1 || report.Observations[0].Kind != NonzeroEmptyEncoding {
		t.Fatalf("empty report: %+v %v", report, err)
	}
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	writer := NewBudgetBuffer(budget)
	_, err = OriginalWire(owned).ReplayTo(writer)
	replay := writer.CompleteBytes()
	if err != nil || !bytes.Equal(replay, received) {
		t.Fatalf("empty replay=%x error=%v", replay, err)
	}
	if fresh := NewBitBuffer().CompleteBytes(); !bytes.Equal(fresh, []byte{0}) {
		t.Fatalf("fresh empty encoding=%x", fresh)
	}
}

func TestTerminalPaddingCanonicalOptionHasNoObservation(t *testing.T) {
	for used := 0; used <= 8; used++ {
		state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
		reader := NewBitBufferFromBytes([]byte{0})
		if err := reader.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadBits(used); err != nil {
			t.Fatal(err)
		}
		padding, err := CaptureFinalBits(reader, "Canonical")
		report, err := FinishDecode(state, err)
		if err != nil || !padding.IsZero() || len(report.Observations) != 0 || len(report.Deviations) != 0 || state.Usage().Reports != 0 {
			t.Fatalf("canonical used=%d padding=%+v report=%+v error=%v", used, padding, report, err)
		}
	}
}

func TestTerminalPaddingReportJSONPreservesDefaultShape(t *testing.T) {
	ordinary, err := json.Marshal(Observation{Kind: UnknownIE})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ordinary, []byte("Padding")) {
		t.Fatalf("default observation gained padding fields: %s", ordinary)
	}
	recorded, err := json.Marshal(Observation{Kind: NonzeroTerminalPadding, PaddingBits: 1, PaddingCount: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(recorded, []byte(`"PaddingBits":1`)) || !bytes.Contains(recorded, []byte(`"PaddingCount":7`)) {
		t.Fatalf("padding fields absent: %s", recorded)
	}
}

type terminalPaddingPrimitive uint8

func TestTerminalPaddingPrimitiveContext(t *testing.T) {
	for _, receiver := range []bool{false, true} {
		for _, tolerate := range []bool{false, true} {
			var options []DecodeOption
			if receiver {
				options = append(options, WithReceiverMode())
			}
			if tolerate {
				options = append(options, WithNonzeroTerminalPadding())
			}
			state := ApplyDecodeOptions(options...)
			bb := NewBitBufferFromBytes([]byte{15})
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			if _, err := bb.ReadBits(4); err != nil {
				t.Fatal(err)
			}
			_, err := CompleteOpenTypeValue(bb, terminalPaddingPrimitive(0))
			report, err := FinishDecode(state, OperationError(err, "Primitive"))
			if !tolerate {
				var located *DecodeError
				if !errors.As(err, &located) || located.Location.Path != "Primitive" || len(report.Deviations) != 1 || report.Deviations[0].Location.Path != "Primitive" {
					t.Fatalf("primitive refusal: %+v %v", report, err)
				}
			} else {
				if err != nil || len(report.Observations) != 1 {
					t.Fatalf("primitive report: %+v %v", report, err)
				}
				o := report.Observations[0]
				if o.Location.Path != "terminalPaddingPrimitive" || o.PaddingBits != 15 || o.PaddingCount != 4 || o.Rule.Clause != "§11.2.1" {
					t.Fatalf("primitive observation: %+v", o)
				}
			}
		}
	}
}

func TestQualifiedPaddingReportNeedsNoAllocation(t *testing.T) {
	root := strings.Repeat("SyntheticType", 16)
	state := ApplyDecodeOptions(WithNonzeroTerminalPadding())
	bb := NewBitBufferFromBytes([]byte{0})
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	state.settings.callReport.Observations = []Observation{{
		Kind:     NonzeroTerminalPadding,
		Location: Location{Path: Path(root + ".Value")},
	}}
	allocations := testing.AllocsPerRun(100, func() {
		if err := bb.qualifyPaddingReports(root); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("already-qualified report allocated %.0f times", allocations)
	}
}
