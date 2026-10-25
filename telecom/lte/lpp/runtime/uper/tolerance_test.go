// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/tolerance_test.go; SHA-256 542a899f17d07b0889cccb12f9349bbd69a90cacf92834325d820a26059269a1.
package uper

import (
	"bytes"
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

// A nested buffer shares the path: contents 10 then three zero bits.

// The log keeps its own copy of the bits.

func TestLeaveComponentRestoresUnbalancedPath(t *testing.T) {
	var log ToleranceLog
	bb := NewBitBufferFromBytes([]byte{0})
	if err := bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log}); err != nil {
		t.Fatal(err)
	}
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

// a one-bit value

func TestToleranceLogConcurrentDecodes(t *testing.T) {
	var log ToleranceLog
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				bb := NewBitBufferFromBytes([]byte{0x80, 0x01})
				if err := bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log}); err != nil {
					t.Error(err)
					return
				}
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
	for kind, want := range map[ToleranceKind]string{ToleratedTrailingBits: "trailing bits", ToleratedTruncatedExtension: "truncated extension", 9: "ToleranceKind(9)"} {
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
			if err := reader.SetDecodeOptions(options); err != nil {
				t.Fatal(err)
			}
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

// TS 36.331 V19.4.0 §8.1 requires a receiver to accept extraneous bits after
// a value in an OCTET STRING (CONTAINING ...). The contained decode inherits
// the parent's options and trace; its record is published with the root's.

// a 3-bit value, then 13 extraneous bits

// Conformant padding, nonzero or not, is retained without a record.

// FuzzContainedBitsRoundTrip checks that any bits after a contained value
// are rejected strictly and, with tolerance, recorded once and reproduced
// exactly by AppendContainedBits.

// not a BIT STRING value: its unused bits are nonzero

// the mandated single zero bit of an empty value

// X.691 (02/2021) 11.1.1 b) and 11.1.4: the contents of an APER BIT STRING
// (CONTAINING ...) are a complete encoding. Its padding is captured, nonzero
// or not, and reproduced while it fills the final octet (go-asn1#103);
// contents that are not whole octets are rejected.

// Padding that no longer fills the final octet is not reproduced.
