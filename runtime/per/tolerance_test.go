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
			wantCount := count
			if value == 0 {
				wantCount = 0 // zero padding is not retained
			}
			if bits, n := final.Bits(); bits != value || n != wantCount || final.IsZero() != (value == 0) {
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
	if _, err := CaptureContainedBits(contained); !errors.Is(err, ErrExtraData) {
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
	kept, err := CaptureContainedBits(contained)
	if n := kept.Trailing().BitLength; err != nil || n != 3 {
		t.Fatalf("contained bits = %d, %v", n, err)
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
		{Path: "Top.List[3].Carried", Kind: ToleratedContainedBits, Offset: 2, Bits: TrailingBits{Bytes: []byte{0}, BitLength: 3}},
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

// TS 36.331 V19.4.0 8.1: with tolerance, any zero or non-zero run after a
// value in a BIT STRING (CONTAINING ...) is accepted, recorded with its
// bits, and reproduced exactly. A strict decode rejects every such run.
func TestContainedBitsAcceptAnyRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		data   []byte
		length int
		after  []byte
	}{
		{"nonzero within seven", []byte{0x10}, 5, []byte{0x20}},
		{"zero beyond seven", []byte{0x00, 0x00}, 10, []byte{0x00, 0x00}},
		{"nonzero beyond seven", []byte{0x7f, 0xff, 0xc0}, 18, []byte{0xff, 0xff, 0x80}},
		{"nonzero beyond an octet boundary", []byte{0x55, 0x55, 0x55, 0x55}, 32, []byte{0xaa, 0xaa, 0xaa, 0xaa}},
	} {
		contained := func(options DecodeOptions) *BitBuffer {
			parent := NewBitBufferFromBytes([]byte{0})
			parent.SetDecodeOptions(options)
			child, err := NewBitBufferFromBits(tc.data, tc.length)
			if err != nil {
				t.Fatal(err)
			}
			child.InheritDecodeOptions(parent)
			if _, err := child.ReadBits(1); err != nil { // a one-bit value
				t.Fatal(err)
			}
			return child
		}
		if _, err := CaptureContainedBits(contained(DecodeOptions{})); !errors.Is(err, ErrExtraData) {
			t.Fatalf("%s: strict error = %v", tc.name, err)
		}
		var log ToleranceLog
		child := contained(DecodeOptions{TrailingBitsTolerance: &log})
		kept, err := CaptureContainedBits(child)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		extra := kept.Trailing()
		if extra.BitLength != tc.length-1 || !bytes.Equal(extra.Bytes, tc.after) {
			t.Fatalf("%s: kept %+v, want %x/%d", tc.name, extra, tc.after, tc.length-1)
		}
		pending := child.trace.pending
		if len(pending) != 1 || pending[0].Kind != ToleratedContainedBits || pending[0].Offset != 1 ||
			pending[0].Bits.BitLength != tc.length-1 || !bytes.Equal(pending[0].Bits.Bytes, tc.after) {
			t.Fatalf("%s: records %+v", tc.name, pending)
		}
		writer := NewBitBuffer()
		if err := writer.WriteBits(uint64(tc.data[0]>>7), 1); err != nil {
			t.Fatal(err)
		}
		if err := AppendContainedBits(writer, kept); err != nil {
			t.Fatal(err)
		}
		if writer.BitsWritten() != tc.length || !bytes.Equal(writer.Bytes(), tc.data) {
			t.Fatalf("%s: re-encoded %x/%d, want %x/%d", tc.name, writer.Bytes(), writer.BitsWritten(), tc.data, tc.length)
		}
	}
	if err := AppendContainedBits(NewBitBuffer(), finalPaddingOf(CompletePadding{bits: 1, count: 3})); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("octet padding in contained bits error = %v", err)
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
	for kind, want := range map[ToleranceKind]string{ToleratedTrailingBits: "trailing bits", ToleratedContainedBits: "contained bits", 9: "ToleranceKind(9)"} {
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
	if kept, err := CaptureContainedBits(contained); err != nil || kept != (FinalPadding{}) || len(contained.trace.pending) != 0 {
		t.Fatalf("contained zero bit: %+v, %v, %+v", kept, err, contained.trace.pending)
	}
	empty, err := NewBitBufferFromBits(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureContainedBits(empty); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("missing contained bit error = %v", err)
	}
	writer := NewBitBuffer()
	if err := AppendContainedBits(writer, FinalPadding{}); err != nil || writer.BitsWritten() != 1 {
		t.Fatalf("contained empty encoding = %d bits, %v", writer.BitsWritten(), err)
	}
	aligned := NewBitBuffer()
	if err := CompleteContainedAligned(aligned); err != nil || !bytes.Equal(aligned.Bytes(), []byte{0}) || aligned.BitsWritten() != 8 {
		t.Fatalf("aligned empty encoding = %x/%d, %v", aligned.Bytes(), aligned.BitsWritten(), err)
	}
}

// TS 36.331 V19.4.0 §8.1 requires a receiver to accept extraneous bits after
// a value in an OCTET STRING (CONTAINING ...). The contained decode inherits
// the parent's options and trace; its record is published with the root's.
func TestContainedFinalBitsJoinParentDecode(t *testing.T) {
	contents := []byte{0xa0, 0xab} // a 3-bit value, then 13 extraneous bits
	contained := func(parent *BitBuffer) *BitBuffer {
		child := NewBitBufferFromBytes(contents)
		child.InheritDecodeOptions(parent)
		if _, err := child.ReadBits(3); err != nil {
			t.Fatal(err)
		}
		return child
	}
	strict := NewBitBufferFromBytes([]byte{0x00})
	strict.SetDecodeOptions(DecodeOptions{})
	if _, err := CaptureContainedFinalBits(contained(strict)); !errors.Is(err, ErrExtraData) {
		t.Fatalf("strict contained suffix error = %v", err)
	}

	var log ToleranceLog
	parent := NewBitBufferFromBytes([]byte{0x00})
	parent.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	mark := parent.EnterComponent("Field")
	final, err := CaptureContainedFinalBits(contained(parent))
	if err != nil {
		t.Fatal(err)
	}
	parent.LeaveComponent(mark)
	if trailing := final.Trailing(); trailing.BitLength != 13 || !bytes.Equal(trailing.Bytes, []byte{0x05, 0x58}) {
		t.Fatalf("retained suffix = %+v", trailing)
	}
	if records := log.Snapshot(); len(records) != 0 {
		t.Fatalf("contained capture published before the root: %+v", records)
	}
	if _, err := parent.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(parent, "Root"); err != nil {
		t.Fatal(err)
	}
	records := log.Snapshot()
	if len(records) != 1 || records[0].Path != "Root.Field" || records[0].Kind != ToleratedTrailingBits ||
		records[0].Offset != 3 || records[0].Bits.BitLength != 13 {
		t.Fatalf("records = %+v", records)
	}

	// Conformant padding, nonzero or not, is retained without a record.
	log.Reset()
	parent = NewBitBufferFromBytes([]byte{0x00})
	parent.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log})
	child := NewBitBufferFromBytes([]byte{0xbf})
	child.InheritDecodeOptions(parent)
	if _, err := child.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	final, err = CaptureContainedFinalBits(child)
	if bits, n := final.Bits(); err != nil || bits != 0x1f || n != 5 {
		t.Fatalf("contained padding = %#x/%d, %v", bits, n, err)
	}
	if _, err := parent.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(parent, "Root"); err != nil || len(log.Snapshot()) != 0 {
		t.Fatalf("conformant padding recorded: %+v, %v", log.Snapshot(), err)
	}
}

// FuzzContainedBitsRoundTrip checks that any bits after a contained value
// are rejected strictly and, with tolerance, recorded once and reproduced
// exactly by AppendContainedBits.
func FuzzContainedBitsRoundTrip(f *testing.F) {
	f.Add([]byte{0x80}, uint8(4), uint8(2))
	f.Add([]byte{0x7f, 0xff, 0xc0}, uint8(18), uint8(1))
	f.Add([]byte{0x00}, uint8(1), uint8(0))
	f.Add([]byte{0x55, 0x55, 0x55, 0x55}, uint8(32), uint8(7))
	f.Fuzz(func(t *testing.T, data []byte, length, consumed uint8) {
		if len(data) > 64 || int(length) > 8*len(data) || consumed > length {
			return
		}
		if _, err := NewBitBufferFromBits(data, int(length)); err != nil {
			return // not a BIT STRING value: its unused bits are nonzero
		}
		read := func(options DecodeOptions) (*BitBuffer, *ToleranceLog) {
			parent := NewBitBufferFromBytes([]byte{0})
			parent.SetDecodeOptions(options)
			child, err := NewBitBufferFromBits(data, int(length))
			if err != nil {
				t.Fatal(err)
			}
			child.InheritDecodeOptions(parent)
			for left := int(consumed); left > 0; left -= min(left, 64) {
				if _, err := child.ReadBits(min(left, 64)); err != nil {
					t.Fatal(err)
				}
			}
			return child, options.TrailingBitsTolerance
		}
		strict, _ := read(DecodeOptions{})
		_, strictErr := CaptureContainedBits(strict)
		var log ToleranceLog
		child, _ := read(DecodeOptions{TrailingBitsTolerance: &log})
		kept, err := CaptureContainedBits(child)
		extra := int(length) - int(consumed)
		if consumed == 0 {
			extra-- // the mandated single zero bit of an empty value
		}
		if extra > 0 && strictErr == nil {
			t.Fatalf("strict decode accepted %d extra bits", extra)
		}
		if err != nil {
			if extra > 0 && consumed != 0 {
				t.Fatalf("tolerant decode rejected %d extra bits: %v", extra, err)
			}
			return
		}
		if extra < 0 {
			extra = 0
		}
		if got := kept.Trailing().BitLength; got != extra || len(child.trace.pending) != min(extra, 1) {
			t.Fatalf("kept %d bits, %d records; want %d", got, len(child.trace.pending), extra)
		}
		writer := NewBitBuffer()
		prefix, err := NewBitBufferFromBits(data, int(length))
		if err != nil {
			t.Fatal(err)
		}
		for range consumed {
			bit, err := prefix.ReadBit()
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteBit(bit); err != nil {
				t.Fatal(err)
			}
		}
		if err := AppendContainedBits(writer, kept); err != nil {
			t.Fatal(err)
		}
		want, err := NewBitBufferFromBits(data, int(length))
		if err != nil {
			t.Fatal(err)
		}
		wantBytes, err := want.ReadBitsToBytes(int(length))
		if err != nil {
			t.Fatal(err)
		}
		if writer.BitsWritten() != int(length) || !bytes.Equal(writer.Bytes(), wantBytes) {
			t.Fatalf("re-encoded %x/%d, want %x/%d", writer.Bytes(), writer.BitsWritten(), wantBytes, length)
		}
	})
}
