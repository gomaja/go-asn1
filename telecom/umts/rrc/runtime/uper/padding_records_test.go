// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/padding_records_test.go; SHA-256 78dfa9f851c9e8f91892378d3a71cd3a411eeeb36896038a1538bc7e0d035dd0.
package uper

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func checkPaddingRecord(t *testing.T, log *ToleranceLog, path, context string, local, input int) {
	t.Helper()
	records := log.Snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%+v", records)
	}
	r := records[0]
	if r.Kind.String() != "nonzero padding" || r.Path != path || r.Offset != local || r.Bits.BitLength != 5 || !bytes.Equal(r.Bits.Bytes, []byte{0x28}) {
		t.Fatalf("record=%+v", r)
	}
	value := reflect.ValueOf(r)
	if got := fmt.Sprint(value.FieldByName("PaddingKind").Interface()); got != context {
		t.Fatalf("padding kind=%s want %s", got, context)
	}
	spans := value.FieldByName("InputSpans")
	if input < 0 {
		if spans.Len() != 0 {
			t.Fatal("invented origin for detached input")
		}
		return
	}
	if spans.Len() != 1 || spans.Index(0).FieldByName("Offset").Int() != int64(input) || spans.Index(0).FieldByName("BitLength").Int() != 5 {
		t.Fatalf("input spans=%v, want %d/5", spans.Interface(), input)
	}
}

// X.691 (02/2021) §§11.1.3.1,11.2.1–11.2.2: completion bits of
// an open type occupy the original input after its length determinant.
func TestPaddingRecordsAtDistinctInputOffsets(t *testing.T) {
	for _, prefix := range []int{3, 11} {
		wire := NewBitBuffer()
		if err := wire.WriteBits(0, prefix); err != nil {
			t.Fatal(err)
		}
		if err := EncodeOpenType(wire, []byte{0x05}); err != nil {
			t.Fatal(err)
		}
		parent := NewBitBufferFromBytes(wire.CompleteBytes())
		var log ToleranceLog
		if err := parent.SetDecodeOptions(toleranceOption(t, "PaddingObservations", &log)); err != nil {
			t.Fatal(err)
		}
		if _, err := parent.ReadBits(prefix); err != nil {
			t.Fatal(err)
		}
		mark := parent.EnterComponent("Group")
		raw, err := DecodeOpenType(parent)
		if err != nil {
			t.Fatal(err)
		}
		child := NewNestedDecodeBuffer(raw, parent)
		if _, err := child.ReadBits(3); err != nil {
			t.Fatal(err)
		}
		padding, err := CaptureOpenTypePadding(child)
		if err != nil {
			t.Fatal(err)
		}
		if v, n := padding.Bits(); v != 5 || n != 5 {
			t.Fatal(padding)
		}
		if len(log.Snapshot()) != 0 {
			t.Fatal("record published before enclosing success")
		}
		parent.LeaveComponent(mark)
		if _, err := CaptureFinalBits(parent, "Synthetic"); err != nil {
			t.Fatal(err)
		}
		checkPaddingRecord(t, &log, "Synthetic.Group", "open type", 3, prefix+8+3)
		snapshot := log.Snapshot()
		snapshot[0].Bits.Bytes[0] = 0
		checkPaddingRecord(t, &log, "Synthetic.Group", "open type", 3, prefix+8+3)
	}
}

func TestPaddingRecordsTopLevelAndDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bb := NewBitBufferFromBytes([]byte{0x05})
		var log ToleranceLog
		options := DecodeOptions{}
		if enabled {
			options = toleranceOption(t, "PaddingObservations", &log)
		}
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBits(3); err != nil {
			t.Fatal(err)
		}
		final, err := CaptureFinalBits(bb, "Synthetic")
		if err != nil {
			t.Fatal(err)
		}
		writer := NewBitBuffer()
		if err := writer.WriteBits(0, 3); err != nil {
			t.Fatal(err)
		}
		out, err := writer.CompleteBytesWithFinalPadding(final)
		if err != nil || !bytes.Equal(out, []byte{5}) {
			t.Fatalf("replay=%x err=%v", out, err)
		}
		if enabled {
			checkPaddingRecord(t, &log, "Synthetic", "final padding", 3, 3)
		} else if len(log.Snapshot()) != 0 {
			t.Fatal("disabled observations recorded")
		}
	}
	bb := NewBitBufferFromBytes([]byte{0})
	var log ToleranceLog
	if err := bb.SetDecodeOptions(toleranceOption(t, "PaddingObservations", &log)); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "Synthetic"); err != nil || len(log.Snapshot()) != 0 {
		t.Fatal("zero padding recorded")
	}
}

func TestPaddingRecordsFragmentedOriginAndFailure(t *testing.T) {
	raw := make([]byte, perFragmentUnit+1)
	raw[len(raw)-1] = 5
	wire := NewBitBuffer()
	if err := EncodeOpenType(wire, raw); err != nil {
		t.Fatal(err)
	}
	bb := NewBitBufferFromBytes(wire.CompleteBytes())
	var log ToleranceLog
	if err := bb.SetDecodeOptions(toleranceOption(t, "PaddingObservations", &log)); err != nil {
		t.Fatal(err)
	}
	contents, err := DecodeOpenType(bb)
	if err != nil {
		t.Fatal(err)
	}
	child := NewNestedDecodeBuffer(contents, bb)
	if _, err := child.ReadBytes(perFragmentUnit); err != nil {
		t.Fatal(err)
	}
	if _, err := child.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureOpenTypePadding(child); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "Fragmented"); err != nil {
		t.Fatal(err)
	}
	checkPaddingRecord(t, &log, "Fragmented", "open type", perFragmentUnit*8+3, perFragmentUnit*8+19)
	log.Reset()
	// A child observation is rolled back by a failed enclosing completion.
	bb = NewBitBufferFromBytes([]byte{0, 0})
	if err := bb.SetDecodeOptions(toleranceOption(t, "PaddingObservations", &log)); err != nil {
		t.Fatal(err)
	}
	child = NewNestedDecodeBuffer([]byte{5}, bb)
	if _, err := child.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureOpenTypePadding(child); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "Failed"); err == nil || len(log.Snapshot()) != 0 {
		t.Fatal("failed decode published records")
	}
}

func TestPaddingRecordEncodingKindsAndUnknownOrigin(t *testing.T) {
	for _, context := range []string{"extension addition", "extension addition group", "choice extension", "open type"} {
		parent := NewBitBufferFromBytes([]byte{0})
		var log ToleranceLog
		if err := parent.SetDecodeOptions(toleranceOption(t, "PaddingObservations", &log)); err != nil {
			t.Fatal(err)
		}
		child := NewNestedDecodeBuffer([]byte{5}, parent)
		if _, err := child.ReadBits(3); err != nil {
			t.Fatal(err)
		}
		var err error
		switch context {
		case "extension addition":
			_, err = CaptureExtensionPadding(child, 2, false)
		case "extension addition group":
			_, err = CaptureExtensionPadding(child, 2, true)
		case "choice extension":
			_, err = CaptureChoicePadding(child, "Selected")
		default:
			mark := child.PaddingComponent("List")
			child.PaddingIndex(1)
			_, err = CaptureOpenTypePadding(child)
			child.LeaveComponent(mark)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parent.ReadBits(1); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureFinalBits(parent, "Root"); err != nil {
			t.Fatal(err)
		}
		path := "Root.ExtData_[2]"
		if context == "choice extension" {
			path = "Root.Selected"
		}
		if context == "open type" {
			path = "Root.List[1]"
		}
		checkPaddingRecord(t, &log, path, context, 3, -1)
	}
}

func TestPaddingAcrossOuterFragment(t *testing.T) {
	payload := NewBitBuffer()
	prefix := perFragmentUnit*8 - 14
	if err := payload.WriteBitsFromBytes(make([]byte, (prefix+7)/8), prefix); err != nil {
		t.Fatal(err)
	}
	if err := EncodeOpenType(payload, []byte{5}); err != nil {
		t.Fatal(err)
	}
	outer := NewBitBuffer()
	if err := EncodeOpenType(outer, payload.CompleteBytes()); err != nil {
		t.Fatal(err)
	}
	var log ToleranceLog
	reader := NewBitBufferFromBytes(outer.CompleteBytes())
	if err := reader.SetDecodeOptions(DecodeOptions{PaddingObservations: &log}); err != nil {
		t.Fatal(err)
	}
	payloadRaw, err := DecodeOpenType(reader)
	if err != nil {
		t.Fatal(err)
	}
	nested := NewNestedDecodeBuffer(payloadRaw, reader)
	if _, err := nested.ReadBitsToBytes(prefix); err != nil {
		t.Fatal(err)
	}
	leafRaw, err := DecodeOpenType(nested)
	if err != nil {
		t.Fatal(err)
	}
	leaf := NewNestedDecodeBuffer(leafRaw, nested)
	if _, err := leaf.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureOpenTypePadding(leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(reader, "Root"); err != nil {
		t.Fatal(err)
	}
	records := log.Snapshot()
	if len(records) != 1 {
		t.Fatal(records)
	}
	want := []InputBitSpan{{perFragmentUnit*8 + 5, 3}, {perFragmentUnit*8 + 16, 2}}
	got := records[0].InputSpans
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

// The collector retains only source intervals and records proportional to the
// number of received open types; it must not copy an ancestor per record.
func TestPaddingObservationStorageIsLinear(t *testing.T) {
	for _, count := range []int{64, 128, 256, 512} {
		wire := bytes.Repeat([]byte{1, 5}, count)
		allocations := testing.AllocsPerRun(1, func() {
			var budget DecodeBudget
			reader := NewDecodeBuffer(wire, &budget)
			var log ToleranceLog
			if err := reader.SetDecodeOptions(DecodeOptions{PaddingObservations: &log}); err != nil {
				panic(err)
			}
			for i := 0; i < count; i++ {
				mark := reader.PaddingComponent("Items")
				reader.PaddingIndex(int64(i))
				raw, err := DecodeOpenType(reader)
				if err != nil {
					panic(err)
				}
				child := NewNestedDecodeBuffer(raw, reader)
				if _, err := child.ReadBits(3); err != nil {
					panic(err)
				}
				if _, err := CaptureOpenTypePadding(child); err != nil {
					panic(err)
				}
				reader.LeaveComponent(mark)
			}
			if len(reader.trace.pending) != count || len(reader.trace.padding.sources) > 2*count {
				panic("collector storage is not linear")
			}
			if _, err := CaptureFinalBits(reader, "Root"); err != nil {
				panic(err)
			}
			if len(log.Snapshot()) != count {
				panic("record count differs")
			}
		})
		if allocations > float64(32*count+32) {
			t.Fatalf("count=%d allocations=%g", count, allocations)
		}
	}
}

func TestPaddingPartialOriginIsReportedAsUnknown(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{1, 0})
	var log ToleranceLog
	if err := parent.SetDecodeOptions(DecodeOptions{PaddingObservations: &log}); err != nil {
		t.Fatal(err)
	}
	raw, err := parent.ReadBitsToBytes(9)
	if err != nil {
		t.Fatal(err)
	}
	child := NewNestedDecodeBuffer(raw, parent)
	// A manually rebound child can include unused storage bits that never
	// arrived in the original nine-bit source. Do not claim a full location.
	if err := child.SetReadBitLength(14); err != nil {
		t.Fatal(err)
	}
	if _, err := child.ReadBits(7); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureOpenTypePadding(child); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(parent, "Root"); err != nil {
		t.Fatal(err)
	}
	records := log.Snapshot()
	if len(records) != 1 || records[0].Bits.BitLength != 7 || len(records[0].InputSpans) != 0 {
		t.Fatalf("partial location presented as complete: %+v", records)
	}
}
