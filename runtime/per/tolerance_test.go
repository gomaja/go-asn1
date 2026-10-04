package per

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestFinalPaddingTableRoundTrip(t *testing.T) {
	for count := uint8(1); count <= 7; count++ {
		for value := uint8(0); value < 1<<count; value++ {
			final := finalPaddingOf(CompletePadding{bits: value, count: count})
			if bits, n := final.Bits(); bits != value || n != count || final.IsZero() != (value == 0) {
				t.Fatalf("finalPaddingOf(%d/%d) = %d/%d zero=%v", value, count, bits, n, final.IsZero())
			}
			bb := NewBitBuffer()
			if err := bb.WriteBits(0, int(8-count)); err != nil {
				t.Fatal(err)
			}
			encoded, err := bb.CompleteBytesWithFinalPadding(final)
			if err != nil || !bytes.Equal(encoded, []byte{value}) {
				t.Fatalf("encode %d/%d = %x, %v", value, count, encoded, err)
			}
		}
	}
	if final := finalPaddingOf(CompletePadding{}); final != (FinalPadding{}) {
		t.Fatal("empty padding is not the zero FinalPadding")
	}
	if a, b := finalPaddingOf(CompletePadding{bits: 3, count: 2}), finalPaddingOf(CompletePadding{bits: 3, count: 2}); a != b {
		t.Fatal("equal paddings do not share a table entry")
	}
}

func TestStrictDecodeHasNoTrace(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0x80, 0xff})
	bb.SetDecodeOptions(DecodeOptions{})
	if bb.trace != nil || bb.EnterComponent("X") != 0 {
		t.Fatal("strict decode allocated a trace")
	}
	if _, err := bb.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "T"); !errors.Is(err, ErrExtraData) {
		t.Fatalf("strict trailing bits error = %v", err)
	}
	contained, err := NewBitBufferFromBits([]byte{0x80}, 4)
	if err != nil {
		t.Fatal(err)
	}
	contained.InheritDecodeOptions(bb)
	if _, err := contained.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureContainedPadding(contained); !errors.Is(err, ErrExtraData) {
		t.Fatalf("strict contained padding error = %v", err)
	}
}

func TestToleranceRecordsCarryPathOffsetAndBits(t *testing.T) {
	var log ToleranceLog
	bb := NewBitBufferFromBytes([]byte{0x80, 0x00, 0xa5})
	bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	if _, err := bb.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	outer := bb.EnterComponent("List")
	index := bb.EnterIndex(3)
	// A nested buffer shares the path: contents 10 then three zero bits.
	contained, err := NewBitBufferFromBits([]byte{0x80}, 5)
	if err != nil {
		t.Fatal(err)
	}
	contained.InheritDecodeOptions(bb)
	field := contained.EnterComponent("Carried")
	if _, err := contained.ReadBits(2); err != nil {
		t.Fatal(err)
	}
	padding, err := CaptureContainedPadding(contained)
	if _, n := padding.Bits(); err != nil || n != 3 {
		t.Fatalf("contained padding = %d bits, %v", n, err)
	}
	contained.LeaveComponent(field)
	bb.LeaveComponent(index)
	bb.LeaveComponent(outer)
	if len(log.Snapshot()) != 0 {
		t.Fatal("records published before the top-level decode finished")
	}
	final, err := CaptureFinalBits(bb, "Top")
	if err != nil {
		t.Fatal(err)
	}
	if trailing := final.Trailing(); trailing.BitLength != 23 || !bytes.Equal(trailing.Bytes, []byte{0x00, 0x01, 0x4a}) {
		t.Fatalf("trailing = %+v", trailing)
	}
	want := []Tolerance{
		{Path: "Top.List[3].Carried", Kind: ToleratedContainedPadding, Offset: 2, Bits: TrailingBits{Bytes: []byte{0}, BitLength: 3}},
		{Path: "Top", Kind: ToleratedTrailingBits, Offset: 1, Bits: TrailingBits{Bytes: []byte{0x00, 0x01, 0x4a}, BitLength: 23}},
	}
	got := log.Snapshot()
	if len(got) != len(want) {
		t.Fatalf("records = %+v", got)
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].Kind != want[i].Kind || got[i].Offset != want[i].Offset ||
			got[i].Bits.BitLength != want[i].Bits.BitLength || !bytes.Equal(got[i].Bits.Bytes, want[i].Bits.Bytes) {
			t.Fatalf("record %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// The log keeps its own copy of the bits.
	final.bits.trailing.Bytes[2] = 0xff
	if log.Snapshot()[1].Bits.Bytes[2] != 0x4a {
		t.Fatal("log aliases the decoded value")
	}
	encoded, err := NewBitBuffer().CompleteBytesWithFinalPadding(FinalPadding{})
	if err != nil || !bytes.Equal(encoded, []byte{0}) {
		t.Fatalf("empty encoding = %x, %v", encoded, err)
	}
	log.Reset()
	if len(log.Snapshot()) != 0 {
		t.Fatal("Reset kept records")
	}
}

func TestLeaveComponentRestoresUnbalancedPath(t *testing.T) {
	var log ToleranceLog
	bb := NewBitBufferFromBytes([]byte{0})
	bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	mark := bb.EnterComponent("A")
	bb.EnterComponent("B") // an inner decoder returned without leaving
	bb.LeaveComponent(mark)
	if path := bb.trace.relativePath(); path != "" {
		t.Fatalf("path after leave = %q", path)
	}
}

func TestContainedPaddingRejectsNonzeroAndLongRuns(t *testing.T) {
	var log ToleranceLog
	parent := NewBitBufferFromBytes([]byte{0})
	parent.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	for _, tc := range []struct {
		data   []byte
		length int
		want   error
	}{
		{[]byte{0x10}, 5, ErrInvalidValue},
		{[]byte{0x00, 0x00}, 10, ErrExtraData},
	} {
		contained, err := NewBitBufferFromBits(tc.data, tc.length)
		if err != nil {
			t.Fatal(err)
		}
		contained.InheritDecodeOptions(parent)
		if _, err := contained.ReadBits(1); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureContainedPadding(contained); !errors.Is(err, tc.want) {
			t.Fatalf("%x/%d error = %v, want %v", tc.data, tc.length, err, tc.want)
		}
	}
	if len(parent.trace.pending) != 0 {
		t.Fatalf("rejected padding was recorded: %+v", parent.trace.pending)
	}
}

func TestToleranceLogConcurrentDecodes(t *testing.T) {
	var log ToleranceLog
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				bb := NewBitBufferFromBytes([]byte{0x80, 0x01})
				bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
				if _, err := bb.ReadBits(1); err != nil {
					t.Error(err)
					return
				}
				if _, err := CaptureFinalBits(bb, "T"); err != nil {
					t.Error(err)
					return
				}
				_ = log.Snapshot()
			}
		}()
	}
	group.Wait()
	if got := len(log.Snapshot()); got != 800 {
		t.Fatalf("records = %d, want 800", got)
	}
}

func TestToleranceKindString(t *testing.T) {
	for kind, want := range map[ToleranceKind]string{ToleratedTrailingBits: "trailing bits", ToleratedContainedPadding: "contained padding", 9: "ToleranceKind(9)"} {
		if got := kind.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", kind, got, want)
		}
	}
}

// FuzzTolerantFinalBitsRoundTrip checks that every accepted final bit run
// re-encodes to the input, that strict decoding never accepts a suffix of
// more than seven bits, and that tolerance records exactly what it accepted.
func FuzzTolerantFinalBitsRoundTrip(f *testing.F) {
	for _, seed := range [][]byte{{0}, {0x8f}, {0x80, 0}, {0x19, 0x40, 0x20, 0, 0}, {0xa0, 0xab}} {
		f.Add(seed, uint16(3))
	}
	// Zero-bit values: the mandated octet alone, with a suffix, and nonzero.
	for _, seed := range [][]byte{{0}, {0, 0xab}, {0x30}, {0x01, 0}} {
		f.Add(seed, uint16(0))
	}
	f.Fuzz(func(t *testing.T, wire []byte, prefix uint16) {
		if len(wire) > 512 || int(prefix) > 8*len(wire) {
			t.Skip()
		}
		for _, tolerant := range []bool{false, true} {
			var log ToleranceLog
			reader := NewBitBufferFromBytes(wire)
			options := DecodeOptions{}
			if tolerant {
				options.TrailingBitsTolerance = &log
			}
			reader.SetDecodeOptions(options)
			consumed, err := reader.ReadBitsToBytes(int(prefix))
			if err != nil {
				t.Fatal(err)
			}
			remaining := reader.BitsRemaining()
			// A value of zero bits is completed by one octet that must be zero
			// (X.691 (02/2021) 11.1.3.1); only bits after it can be a suffix.
			zeroBit := prefix == 0
			final, err := CaptureFinalBits(reader, "T")
			records := log.Snapshot()
			if err != nil {
				if len(records) != 0 {
					t.Fatalf("failed capture recorded %+v", records)
				}
				if tolerant && remaining > 7 && (!zeroBit || wire[0] == 0) {
					t.Fatalf("tolerant capture rejected %d bits: %v", remaining, err)
				}
				continue
			}
			if !tolerant && remaining > 8 {
				t.Fatalf("strict capture accepted %d bits", remaining)
			}
			wantRecord := tolerant && remaining > 7 && (!zeroBit || remaining != 8)
			if wantRecord != (len(records) == 1) || len(records) > 1 {
				t.Fatalf("remaining %d: records %+v", remaining, records)
			}
			wantOffset, wantBits := int(prefix), remaining
			if zeroBit {
				wantOffset, wantBits = 8, remaining-8
			}
			if wantRecord && (records[0].Kind != ToleratedTrailingBits || records[0].Offset != wantOffset || records[0].Bits.BitLength != wantBits || records[0].Path != "T") {
				t.Fatalf("record = %+v, prefix %d, remaining %d", records[0], prefix, remaining)
			}
			writer := NewBitBuffer()
			if err := writer.WriteBitsFromBytes(consumed, int(prefix)); err != nil {
				t.Fatal(err)
			}
			got, err := writer.CompleteBytesWithFinalPadding(final)
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("round trip = %x, %v; want %x", got, err, wire)
			}
		}
	})
}

// X.691 (02/2021) 11.1.3.1, 11.1.3.2 and 11.1.4: the complete encoding of an
// empty value is one zero octet, or one zero bit inside a UPER BIT STRING.
// Neither is padding or a tolerated suffix.
func TestZeroBitCompleteEncodingsAreNotTolerances(t *testing.T) {
	var log ToleranceLog
	bb := NewBitBufferFromBytes([]byte{0})
	bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	final, err := CaptureFinalBits(bb, "T")
	if err != nil || final != (FinalPadding{}) || len(log.Snapshot()) != 0 {
		t.Fatalf("zero octet: final %+v, err %v, records %+v", final, err, log.Snapshot())
	}
	bb = NewBitBufferFromBytes([]byte{0x80})
	bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	if _, err := CaptureFinalBits(bb, "T"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nonzero octet error = %v", err)
	}
	contained, err := NewBitBufferFromBits([]byte{0}, 1)
	if err != nil {
		t.Fatal(err)
	}
	contained.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	if padding, err := CaptureContainedPadding(contained); err != nil || padding != (CompletePadding{}) || len(contained.trace.pending) != 0 {
		t.Fatalf("contained zero bit: %+v, %v, %+v", padding, err, contained.trace.pending)
	}
	empty, err := NewBitBufferFromBits(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureContainedPadding(empty); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("missing contained bit error = %v", err)
	}
	writer := NewBitBuffer()
	if err := AppendContainedZeroPadding(writer, CompletePadding{}); err != nil || writer.BitsWritten() != 1 {
		t.Fatalf("contained empty encoding = %d bits, %v", writer.BitsWritten(), err)
	}
	aligned := NewBitBuffer()
	if err := CompleteContainedAligned(aligned); err != nil || !bytes.Equal(aligned.Bytes(), []byte{0}) || aligned.BitsWritten() != 8 {
		t.Fatalf("aligned empty encoding = %x/%d, %v", aligned.Bytes(), aligned.BitsWritten(), err)
	}
}
