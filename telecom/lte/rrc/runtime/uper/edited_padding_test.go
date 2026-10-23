// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/edited_padding_test.go; SHA-256 0e5927afa2309debe6706da911aabffd24e8e4296c8178e4d98ae95c1d0685e5.
package uper

import (
	"bytes"
	"testing"
)

// writeBits writes the first n bits of data, MSB first, to a new buffer.
func writeBits(t *testing.T, data []byte, n int) *BitBuffer {
	t.Helper()
	bb := NewBitBuffer()
	if err := bb.WriteBitsFromBytes(data, n); err != nil {
		t.Fatal(err)
	}
	return bb
}

// freshComplete is the complete encoding a new value of n bits receives:
// X.691 (02/2021) 11.1.3.1 and 11.1.4 append zero bits, or replace an empty
// encoding with one zero octet.
func freshComplete(t *testing.T, data []byte, n int) []byte {
	t.Helper()
	return append([]byte(nil), writeBits(t, data, n).CompleteBytes()...)
}

// Observed all-zero padding is what an encoder writes anyway, so a decoder
// keeps nothing and an edited value never fails on it (go-asn1#90).
func TestZeroPaddingIsNotRetained(t *testing.T) {
	for _, capture := range []func(*BitBuffer) (CompletePadding, error){CaptureFinalPadding, CaptureOpenTypePadding} {
		bb := NewBitBufferFromBytes([]byte{0x80})
		if _, err := bb.ReadBits(2); err != nil {
			t.Fatal(err)
		}
		padding, err := capture(bb)
		if err != nil || padding != (CompletePadding{}) {
			t.Fatalf("zero padding = %+v, %v; want none retained", padding, err)
		}
	}
	for _, tolerant := range []bool{false, true} {
		bb := NewBitBufferFromBytes([]byte{0x80})
		if tolerant {
			if err := bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &ToleranceLog{}}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := bb.ReadBits(2); err != nil {
			t.Fatal(err)
		}
		final, err := CaptureFinalBits(bb, "T")
		if err != nil || final != (FinalPadding{}) {
			t.Fatalf("tolerant=%v: zero final bits = %+v, %v; want none retained", tolerant, final, err)
		}
	}
}

// The go-asn1#90 shape: a value decoded from 00 (two value bits, six zero
// padding bits) gains two bits and must encode as a new value would.
func TestEditedValueAfterZeroPadding(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0x00})
	if _, err := bb.ReadBits(2); err != nil {
		t.Fatal(err)
	}
	final, err := CaptureFinalBits(bb, "T")
	if err != nil {
		t.Fatal(err)
	}
	edited := writeBits(t, []byte{0x40}, 4)
	got, err := edited.CompleteBytesWithFinalPadding(final)
	if err != nil || !bytes.Equal(got, []byte{0x40}) {
		t.Fatalf("edited = %x, %v; want 40", got, err)
	}
}

// Observed padding that no longer completes the final octet of the new
// encoding is replaced by the zero padding of X.691 (02/2021) 11.1.3.1 and
// 11.1.4. Padding that still fits is kept: see CompleteBytesWithPadding.
func TestEditedValueReplacesNonzeroPadding(t *testing.T) {
	// 1010 1111: four value bits and four nonzero padding bits.
	for _, capture := range []func(*BitBuffer) (CompletePadding, error){CaptureFinalPadding, CaptureOpenTypePadding} {
		bb := NewBitBufferFromBytes([]byte{0xaf})
		if _, err := bb.ReadBits(4); err != nil {
			t.Fatal(err)
		}
		padding, err := capture(bb)
		if err != nil {
			t.Fatal(err)
		}
		for _, edit := range []struct {
			data []byte
			bits int
			want []byte
		}{
			{[]byte{0xa0}, 4, []byte{0xaf}},              // unchanged
			{[]byte{0x50}, 4, []byte{0x5f}},              // same length: the residual rule
			{[]byte{0xa8}, 5, []byte{0xa8}},              // one bit longer
			{[]byte{0x80}, 3, []byte{0x80}},              // one bit shorter
			{[]byte{0xa0, 0x00}, 12, []byte{0xa0, 0x0f}}, // one octet longer: the residual rule
			{nil, 0, []byte{0x00}},                       // empty encoding
			{[]byte{0xab}, 8, []byte{0xab}},              // no padding needed
		} {
			got, err := writeBits(t, edit.data, edit.bits).CompleteBytesWithPadding(padding)
			if err != nil || !bytes.Equal(got, edit.want) {
				t.Fatalf("%d bits: encoded %x, %v; want %x", edit.bits, got, err, edit.want)
			}
			final, err := writeBits(t, edit.data, edit.bits).CompleteBytesWithFinalPadding(finalPaddingOf(padding))
			if err != nil || !bytes.Equal(final, edit.want) {
				t.Fatalf("%d bits: final encoded %x, %v; want %x", edit.bits, final, err, edit.want)
			}
		}
	}
}

// A tolerated suffix after the value (TS 36.331 V19.4.0 8.1) belongs to the
// received encoding. It is replayed only after that encoding, bit for bit;
// an edited value is completed as a new one, so it decodes strictly.
func TestEditedValueDropsTrailingBits(t *testing.T) {
	// x = 5 in three bits, then thirteen extraneous bits.
	wire := []byte{0xa0, 0xab}
	bb := NewBitBufferFromBytes(wire)
	if err := bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	final, err := CaptureFinalBits(bb, "T")
	if err != nil || final.Trailing().BitLength != 13 {
		t.Fatalf("captured %+v, %v", final.Trailing(), err)
	}
	for _, edit := range []struct {
		data []byte
		bits int
		want []byte
	}{
		{[]byte{0xa0}, 3, wire},                      // unchanged
		{[]byte{0x60}, 3, []byte{0x60}},              // same length, other bits
		{[]byte{0xa0}, 4, []byte{0xa0}},              // one bit longer
		{[]byte{0xa0, 0x00}, 11, []byte{0xa0, 0x00}}, // one octet longer
		{nil, 0, []byte{0x00}},                       // empty encoding
	} {
		got, err := writeBits(t, edit.data, edit.bits).CompleteBytesWithFinalPadding(final)
		if err != nil || !bytes.Equal(got, edit.want) {
			t.Fatalf("%d bits: encoded %x, %v; want %x", edit.bits, got, err, edit.want)
		}
	}

	// An empty value is completed by its mandated zero octet; a suffix after
	// it is replayed only for an empty value.
	empty := NewBitBufferFromBytes([]byte{0x00, 0xab})
	if err := empty.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	final, err = CaptureFinalBits(empty, "T")
	if err != nil || final.Trailing().BitLength != 8 {
		t.Fatalf("empty captured %+v, %v", final.Trailing(), err)
	}
	if got, err := NewBitBuffer().CompleteBytesWithFinalPadding(final); err != nil || !bytes.Equal(got, []byte{0x00, 0xab}) {
		t.Fatalf("empty unchanged = %x, %v", got, err)
	}
	if got, err := writeBits(t, []byte{0x80}, 1).CompleteBytesWithFinalPadding(final); err != nil || !bytes.Equal(got, []byte{0x80}) {
		t.Fatalf("empty edited = %x, %v; want 80", got, err)
	}
}

// Bits after a value in a BIT STRING (CONTAINING ...) are replayed only after
// the encoding they followed. X.691 (02/2021) 11.1.3.2 gives a new encoding
// no padding at all.

// Two value bits (10), then six extraneous bits 101101.

// unchanged
// same length, other bits
// one bit longer
// one bit shorter
// eight bits longer
// empty: the single zero bit

// An empty value's extra bits follow its mandated zero bit.

// FuzzEditedFinalBits decodes a complete encoding, strictly and with
// tolerance, then encodes another value with the final bits it retained. An
// unchanged value re-encodes to the input. Any other value encodes without
// error and decodes strictly to its bits. It is the value's fresh encoding,
// except that nonzero padding of the width the new encoding needs is kept.
func FuzzEditedFinalBits(f *testing.F) {
	f.Add([]byte{0x00}, uint16(2), []byte{0x40}, uint16(4)) // go-asn1#90
	f.Add([]byte{0xaf}, uint16(4), []byte{0xa8}, uint16(5))
	f.Add([]byte{0xaf}, uint16(4), []byte{0x50}, uint16(4))
	f.Add([]byte{0xaf}, uint16(4), []byte{0xa0, 0}, uint16(12))
	f.Add([]byte{0xa0, 0xab}, uint16(3), []byte{0xa0, 0}, uint16(11))
	f.Add([]byte{0xa0, 0xab}, uint16(3), []byte{0x60}, uint16(3))
	f.Add([]byte{0x00, 0xab}, uint16(0), []byte{0xff}, uint16(8))
	f.Add([]byte{0x00, 0xab}, uint16(0), []byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, wire []byte, prefix uint16, edit []byte, editBits uint16) {
		if len(wire) > 256 || len(edit) > 256 || int(prefix) > 8*len(wire) || int(editBits) > 8*len(edit) {
			t.Skip()
		}
		edited := writeBits(t, edit, int(editBits)).Bytes()
		fresh := freshComplete(t, edit, int(editBits))
		for _, tolerant := range []bool{false, true} {
			reader := NewBitBufferFromBytes(wire)
			if tolerant {
				if err := reader.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &ToleranceLog{}}); err != nil {
					t.Fatal(err)
				}
			}
			consumed, err := reader.ReadBitsToBytes(int(prefix))
			if err != nil {
				t.Fatal(err)
			}
			final, err := CaptureFinalBits(reader, "T")
			if err != nil {
				continue
			}
			unchanged, err := writeBits(t, consumed, int(prefix)).CompleteBytesWithFinalPadding(final)
			if err != nil || !bytes.Equal(unchanged, wire) {
				t.Fatalf("unchanged = %x, %v; want %x", unchanged, err, wire)
			}
			got, err := writeBits(t, edit, int(editBits)).CompleteBytesWithFinalPadding(final)
			if err != nil {
				t.Fatalf("edited %x/%d: %v", edit, editBits, err)
			}
			sameValue := editBits == prefix && bytes.Equal(edited, writeBits(t, consumed, int(prefix)).Bytes())
			suffix := final.Trailing().BitLength != 0
			paddingBits, paddingCount := final.Bits()
			padded := paddingCount != 0 && editBits != 0 && int(paddingCount) == (8-int(editBits)%8)%8
			switch {
			case sameValue:
				if !bytes.Equal(got, wire) {
					t.Fatalf("same value = %x, want %x", got, wire)
				}
				continue
			case padded && (!bytes.Equal(got[:len(got)-1], fresh[:len(fresh)-1]) || got[len(got)-1] != fresh[len(fresh)-1]|paddingBits):
				t.Fatalf("edited %x/%d = %x, want fresh %x with padding %#x", edit, editBits, got, fresh, paddingBits)
			case !padded && !bytes.Equal(got, fresh):
				t.Fatalf("edited %x/%d = %x, want fresh %x (suffix %v)", edit, editBits, got, fresh, suffix)
			}
			check := NewBitBufferFromBytes(got)
			decoded, err := check.ReadBitsToBytes(int(editBits))
			if err != nil || !bytes.Equal(decoded, edited) {
				t.Fatalf("decoded %x, %v; want %x", decoded, err, edited)
			}
			if _, err := CaptureFinalBits(check, "T"); err != nil {
				t.Fatalf("edited encoding %x does not decode: %v", got, err)
			}
		}
	})
}

// FuzzEditedContainedBits is FuzzEditedFinalBits for a value carried in a
// BIT STRING (CONTAINING ...): any value other than the decoded one gets its
// fresh encoding, which has no bits after it (X.691 (02/2021) 11.1.3.2).

// not a BIT STRING value: its unused bits are nonzero

// Retaining final bits must stay free on the strict path (go-asn1#76):
// capturing 0–7 padding bits never allocates, and completing an encoding
// copies it only to apply nonzero observed padding.
func TestFinalBitsAllocations(t *testing.T) {
	for _, wire := range [][]byte{{0x80}, {0xbf}} {
		if allocs := testing.AllocsPerRun(100, func() {
			var budget DecodeBudget
			bb := NewDecodeBuffer(wire, &budget)
			if err := bb.SetDecodeOptions(DecodeOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := bb.ReadBits(2); err != nil {
				t.Fatal(err)
			}
			if _, err := CaptureFinalBits(bb, "T"); err != nil {
				t.Fatal(err)
			}
		}); allocs != 0 {
			t.Fatalf("capture %x allocates %.0f times", wire, allocs)
		}
	}
	bb := writeBits(t, []byte{0x80}, 2)
	nonzero := finalPaddingOf(CompletePadding{bits: 0x3f, count: 6})
	for _, tc := range []struct {
		name   string
		encode func() ([]byte, error)
		want   float64
	}{
		{"new value", func() ([]byte, error) { return bb.CompleteBytesWithFinalPadding(FinalPadding{}) }, 0},
		{"zero padding", func() ([]byte, error) { return bb.CompleteBytesWithPadding(CompletePadding{}) }, 0},
		{"padding of another width", func() ([]byte, error) { return bb.CompleteBytesWithPadding(CompletePadding{bits: 1, count: 1}) }, 0},
		{"nonzero padding", func() ([]byte, error) { return bb.CompleteBytesWithFinalPadding(nonzero) }, 1},
	} {
		if allocs := testing.AllocsPerRun(100, func() {
			if _, err := tc.encode(); err != nil {
				t.Fatal(err)
			}
		}); allocs != tc.want {
			t.Fatalf("%s: complete allocates %.0f times, want %.0f", tc.name, allocs, tc.want)
		}
	}
}
