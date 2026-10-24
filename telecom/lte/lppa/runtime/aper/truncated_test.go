// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/truncated_test.go; SHA-256 03c4c4d6d4f7cceecd0fd4f4b2358e9befd5ca525611658c71096b595e8366d0.
package aper

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

// holder models a generated extensible SEQUENCE { flag BOOLEAN, ... } whose
// extension additions are kept as open type contents, preceded in the
// outermost encoding by lead bits (an enclosing value's bits).
type holder struct {
	lead    []uint8
	flag    bool
	count   int64
	present []bool
	data    [][]byte
	final   FinalPadding
}

// encodeHolder writes h as the generated encoder does: the extension bit and
// bitmap follow the typed state, then AppendTruncatedExtension completes it.
func encodeHolder(t *testing.T, h *holder, aligned bool) []byte {
	t.Helper()
	encoded, _ := encodeHolderAt(t, h, aligned)
	return encoded
}

// encodeHolderAt also returns the position of each present addition's open
// type, before any alignment padding.
func encodeHolderAt(t *testing.T, h *holder, aligned bool) ([]byte, map[int64]int) {
	t.Helper()
	starts := map[int64]int{}
	bb := NewBitBuffer()
	for _, bit := range h.lead {
		if err := bb.WriteBit(bit); err != nil {
			t.Fatal(err)
		}
	}
	hasExtensions := h.count > 0 || len(h.data) > 0
	if err := EncodeBoolean(bb, hasExtensions); err != nil {
		t.Fatal(err)
	}
	if err := EncodeBoolean(bb, h.flag); err != nil {
		t.Fatal(err)
	}
	if hasExtensions {
		length := EncodeNormallySmallLengthAligned
		if aligned {
			length = EncodeNormallySmallLengthAligned
		}
		if err := length(bb, h.count+1); err != nil {
			t.Fatal(err)
		}
		present := func(i int64) bool {
			return i < int64(len(h.present)) && h.present[i] || i < int64(len(h.data)) && h.data[i] != nil
		}
		for i := int64(0); i <= h.count; i++ {
			if err := EncodeBoolean(bb, present(i)); err != nil {
				t.Fatal(err)
			}
		}
		for i := int64(0); i <= h.count; i++ {
			if !present(i) {
				continue
			}
			encode := EncodeOpenTypeAligned
			if aligned {
				encode = EncodeOpenTypeAligned
			}
			starts[i] = bb.BitsWritten()
			if err := encode(bb, h.data[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	AppendTruncatedExtension(bb, h.final)
	encoded, err := bb.CompleteBytesWithFinalPadding(FinalPadding{})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), encoded...), starts
}

// decodeHolder reads h as the generated decoder does.
func decodeHolder(bb *BitBuffer, leadBits int, aligned bool) (*holder, error) {
	h := &holder{}
	for range leadBits {
		bit, err := bb.ReadBit()
		if err != nil {
			return nil, err
		}
		h.lead = append(h.lead, bit)
	}
	additions := BeginExtensionAdditions(bb)
	hasExtensions, err := DecodeBoolean(bb)
	if err != nil {
		return nil, err
	}
	if h.flag, err = DecodeBoolean(bb); err != nil {
		return nil, err
	}
	if hasExtensions {
		decodeBitmap := additions.DecodeBitmapAligned
		if aligned {
			decodeBitmap = additions.DecodeBitmapAligned
		}
		count, present, err := decodeBitmap(bb)
		if err != nil {
			return nil, err
		}
		h.count, h.present, h.data = count, present, make([][]byte, count+1)
		for i := int64(0); i <= count; i++ {
			if present[i] && additions.Received(bb, i) {
				decode := DecodeOpenTypeAligned
				if aligned {
					decode = DecodeOpenTypeAligned
				}
				data, err := decode(bb)
				if err != nil {
					return nil, err
				}
				h.data[i] = data
			}
		}
		if additions.Emptied() {
			h.count, h.present, h.data = 0, nil, nil
		}
	}
	h.final = additions.Record(h.final)
	return h, nil
}

func decodeTop(data []byte, leadBits int, aligned bool, options decodeSettings) (*holder, error) {
	bb := NewBitBufferFromBytes(data)
	if aligned {
		if err := bb.setDecodeSettingsAligned(options); err != nil {
			return nil, err
		}
	} else {
		if err := bb.setDecodeSettingsAligned(options); err != nil {
			return nil, err
		}
	}
	h, err := decodeHolder(bb, leadBits, aligned)
	if err != nil {
		return nil, err
	}
	padding, err := CaptureFinalBits(bb, "Top")
	if err != nil {
		return nil, err
	}
	h.final = padding.WithRecords(h.final)
	return h, nil
}

// fullHolder has three present additions after two lead bits; the second is
// 3 octets long.
func fullHolder() *holder {
	return &holder{lead: []uint8{1, 0}, flag: true, count: 2, present: []bool{true, true, true}, data: [][]byte{{0x5a}, {0x01, 0x02, 0x03}, {0x77}}}
}

func TestTruncatedExtensionCutInContents(t *testing.T) {
	for _, aligned := range []bool{true} {
		full, starts := encodeHolderAt(t, fullHolder(), aligned)
		// The second addition's open type starts after the lead bits,
		// extension bit, flag, bitmap length, three bitmap bits and the first
		// addition's two octets: at bit 30, or 32 once APER aligns them.
		offset := starts[1]
		if want := map[bool]int{false: 30, true: 32}[aligned]; offset != want {
			t.Fatalf("aligned=%v: second addition at bit %d, want %d", aligned, offset, want)
		}
		cut := full[:(offset+8)/8+1] // its length octet and part of its contents
		var log ToleranceLog
		if _, err := decodeTop(cut, 2, aligned, decodeSettings{}); !errors.Is(err, ErrTruncated) {
			t.Fatalf("aligned=%v: strict decode of a cut addition = %v, want ErrTruncated", aligned, err)
		}
		h, err := decodeTop(cut, 2, aligned, decodeSettings{TruncatedExtensionTolerance: &log})
		if err != nil {
			t.Fatalf("aligned=%v: tolerant decode: %v", aligned, err)
		}
		if suffix := h.final.Trailing(); suffix.BitLength != 0 || len(suffix.Bytes) != 0 {
			t.Fatalf("cut created a trailing suffix: %+v", suffix)
		}
		if !h.flag || h.count != 2 || !bytes.Equal(h.data[0], []byte{0x5a}) || h.data[1] != nil || h.data[2] != nil {
			t.Fatalf("aligned=%v: decoded %+v", aligned, h)
		}
		if want := []bool{true, false, false}; !equalBools(h.present, want) {
			t.Fatalf("aligned=%v: present = %v, want %v", aligned, h.present, want)
		}
		records := log.Snapshot()
		if len(records) != 1 {
			t.Fatalf("aligned=%v: records = %+v", aligned, records)
		}
		record := records[0]
		received := 8*len(cut) - offset
		if record.Path != "Top.ExtData_[1]" || record.Kind != ToleratedTruncatedExtension || record.Offset != offset ||
			record.Bits.BitLength != received || record.Missing != 3*8-(received-8) {
			t.Fatalf("aligned=%v: record = %+v (offset %d, received %d)", aligned, record, offset, received)
		}
		if tail := bitsFrom(cut, offset); !bytes.Equal(record.Bits.Bytes, tail) {
			t.Fatalf("aligned=%v: record bits %x, want %x", aligned, record.Bits.Bytes, tail)
		}
		if !h.final.Truncated() {
			t.Fatalf("aligned=%v: the decoded value lost its cut record", aligned)
		}
		if got := encodeHolder(t, h, aligned); !bytes.Equal(got, cut) {
			t.Fatalf("aligned=%v: unchanged replay = %x, want %x", aligned, got, cut)
		}
		// An edit before the cut gives a new encoding without the cut
		// additions, which strict decoding accepts.
		h.flag = false
		edited := encodeHolder(t, h, aligned)
		strict, err := decodeTop(edited, 2, aligned, decodeSettings{})
		if err != nil || strict.flag || strict.count != 2 || !equalBools(strict.present, []bool{true, false, false}) || !bytes.Equal(strict.data[0], []byte{0x5a}) {
			t.Fatalf("aligned=%v: edited value %x decodes to %+v, %v", aligned, edited, strict, err)
		}
	}
}

// bitsFrom returns the bits of data from offset to its end, MSB first.
func bitsFrom(data []byte, offset int) []byte {
	bb := NewBitBufferFromBytes(data)
	bb.bitPos = offset
	tail, err := bb.ReadBitsToBytes(bb.BitsRemaining())
	if err != nil {
		panic(err)
	}
	return tail
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A cut inside a length determinant has no declared length: Missing is -1.
func TestTruncatedExtensionCutInLengthDeterminant(t *testing.T) {
	long := fullHolder()
	long.data[1] = bytes.Repeat([]byte{0xc3}, 200) // two-octet length 0x80c8
	for _, aligned := range []bool{true} {
		full, starts := encodeHolderAt(t, long, aligned)
		offset := starts[1]
		// The first cut leaves two bits of the length determinant (none in
		// APER, where the open type starts on an octet), the second one more
		// octet, still short of the two-octet determinant 80c8.
		for _, cutAt := range []int{(offset + 7) / 8, (offset+7)/8 + 1} {
			cut := full[:cutAt]
			var log ToleranceLog
			h, err := decodeTop(cut, 2, aligned, decodeSettings{TruncatedExtensionTolerance: &log})
			if err != nil {
				t.Fatalf("aligned=%v cut %d: %v", aligned, cutAt, err)
			}
			records := log.Snapshot()
			if len(records) != 1 || records[0].Missing != -1 || records[0].Offset != offset || records[0].Bits.BitLength != 8*len(cut)-offset {
				t.Fatalf("aligned=%v cut %d: records %+v", aligned, cutAt, records)
			}
			if got := encodeHolder(t, h, aligned); !bytes.Equal(got, cut) {
				t.Fatalf("aligned=%v cut %d: replay %x, want %x", aligned, cutAt, got, cut)
			}
		}
	}
}

// When the cut addition is the first present one, no addition remains: the
// value decodes as one without extensions, and an edit encodes it with a
// zero extension bit (X.691 (02/2021) 19.1).
func TestTruncatedExtensionEmptiedValue(t *testing.T) {
	for _, aligned := range []bool{true} {
		value := &holder{lead: []uint8{0, 1, 1}, flag: true, count: 2, present: []bool{false, true, true}, data: [][]byte{nil, {0x01, 0x02}, {0x03}}}
		full := encodeHolder(t, value, aligned)
		cut := full[:len(full)-3]
		var log ToleranceLog
		h, err := decodeTop(cut, 3, aligned, decodeSettings{TruncatedExtensionTolerance: &log})
		if err != nil {
			t.Fatalf("aligned=%v: %v", aligned, err)
		}
		if h.count != 0 || h.present != nil || h.data != nil || !h.flag {
			t.Fatalf("aligned=%v: emptied value %+v", aligned, h)
		}
		if records := log.Snapshot(); len(records) != 1 || records[0].Path != "Top.ExtData_[1]" {
			t.Fatalf("aligned=%v: records %+v", aligned, records)
		}
		if got := encodeHolder(t, h, aligned); !bytes.Equal(got, cut) {
			t.Fatalf("aligned=%v: replay %x, want %x", aligned, got, cut)
		}
		h.lead[0] = 1
		edited := encodeHolder(t, h, aligned)
		// lead 111, extension bit 0, flag 1: 1110 1000.
		if !bytes.Equal(edited, []byte{0xe8}) {
			t.Fatalf("aligned=%v: edited emptied value = %x, want e8", aligned, edited)
		}
	}
}

// An invalid length determinant is reported, not taken for a cut.
func TestTruncatedExtensionInvalidDeterminantIsAnError(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0x80, 0x05}) // non-minimal two-octet length 5
	if err := bb.setDecodeSettingsAligned(decodeSettings{TruncatedExtensionTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	if missing, cut := openTypeCut(*bb, false); cut || missing != 0 {
		t.Fatalf("non-minimal determinant read as a cut: %d %v", missing, cut)
	}
	// A first fragment of 16K octets followed by a cut determinant.
	data := make([]byte, 1+16384)
	data[0] = 0xc1
	if missing, cut := openTypeCut(*NewBitBufferFromBytes(data), false); !cut || missing != -1 {
		t.Fatalf("cut after a full fragment = %d %v", missing, cut)
	}
	if missing, cut := openTypeCut(*NewBitBufferFromBytes(data[:100]), false); !cut || missing != 8*(16384-99) {
		t.Fatalf("cut inside a fragment = %d %v", missing, cut)
	}
}

func TestSetDecodeSettingsAlignedRejectsUnsupportedOptions(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0})
	if err := bb.setDecodeSettingsAligned(decodeSettings{TrailingBitsTolerance: &ToleranceLog{}}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("TrailingBitsTolerance: %v", err)
	}
	if err := bb.setDecodeSettingsAligned(decodeSettings{ContainedDecoding: DeferAll, Deferrals: &DeferralLog{}}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("DeferAll: %v", err)
	}
	if err := bb.setDecodeSettingsAligned(decodeSettings{TruncatedExtensionTolerance: &ToleranceLog{}, MaxZeroWidthCharacters: 3}); err != nil || !bb.outermost {
		t.Fatalf("supported options: %v", err)
	}
}

// The outermost flag is never inherited by a nested buffer.
func TestOutermostFlagIsNotInherited(t *testing.T) {
	if size := unsafe.Sizeof(BitBuffer{}); unsafe.Sizeof(uintptr(0)) == 8 && size != 64 {
		t.Fatalf("BitBuffer is %d bytes", size)
	}
	top := NewBitBufferFromBytes([]byte{0})
	if err := top.setDecodeSettingsAligned(decodeSettings{TruncatedExtensionTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	nested := NewBitBufferFromBytes([]byte{0})
	nested.InheritDecodeOptions(top)
	if !top.outermost || nested.outermost {
		t.Fatalf("outermost: top %v, nested %v", top.outermost, nested.outermost)
	}
	if err := top.setDecodeSettingsAligned(decodeSettings{}); err != nil {
		t.Fatal(err)
	}
	if top.outermost {
		t.Fatal("a strict decode marked the input outermost")
	}
}

// The cut record expects exactly the encoding an unchanged decoded value
// gets: each segment it compares is checked by flipping one bit in it.
func TestTruncatedExtensionCutRecordComparesEverySegment(t *testing.T) {
	input := []byte{0xb5, 0x5b, 0xf0, 0x0f, 0x3c, 0xc3}
	bit := func(data []byte, position int) byte { return data[position/8] >> (7 - position%8) & 1 }
	writer := func(bits []byte, length int) *BitBuffer {
		bb := NewBitBuffer()
		if err := bb.WriteBitsFromBytes(bits, length); err != nil {
			t.Fatal(err)
		}
		return bb
	}
	flip := func(bits []byte, position int) []byte {
		out := append([]byte(nil), bits...)
		out[position/8] ^= 0x80 >> (position % 8)
		return out
	}
	// kept: the extension bit at 3, the bitmap length at 5, the bitmap's
	// bits 12 to 16, addition 2 of 4 cut at bit 30; the expected encoding
	// clears bitmap bits 14 and 15.
	kept := ExtensionAdditions{start: 3, root: 5, bitmap: 12, end: 16, present: []bool{true, false, true, true}}
	record, err := kept.cutRecord(NewBitBufferFromBytes(input), input, 2, 30, true)
	if err != nil {
		t.Fatal(err)
	}
	if bit(input, 14) != 1 || bit(input, 15) != 1 {
		t.Fatal("test input lacks set bitmap bits 14 and 15")
	}
	expected := flip(flip(input, 14), 15)
	if record.expectedBits != 30 || !record.follows(writer(expected, 30)) {
		t.Fatalf("the unchanged encoding does not follow: %x/%d", record.expected, record.expectedBits)
	}
	for _, position := range []int{0, 3, 13, 14, 15, 16, 29} {
		if record.follows(writer(flip(expected, position), 30)) {
			t.Fatalf("a change at bit %d still follows", position)
		}
	}
	if record.follows(writer(expected, 29)) || record.follows(writer(expected, 31)) {
		t.Fatal("an encoding of another length follows")
	}
	// One more zero bit leaves the octets unchanged: only the length tells.
	longer := writer(expected, 30)
	if err := longer.WriteBit(0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(longer.Bytes(), record.expected) || record.follows(longer) {
		t.Fatal("an encoding one zero bit longer follows")
	}
	// emptied: the extension bit at 3 is cleared, and the value ends with its
	// root at bit 9.
	emptied := ExtensionAdditions{start: 3, root: 9, bitmap: 12, end: 16, present: []bool{false, true, false, false}}
	record, err = emptied.cutRecord(NewBitBufferFromBytes(input), input, 1, 20, false)
	if err != nil {
		t.Fatal(err)
	}
	if bit(input, 3) != 1 {
		t.Fatal("test input has its extension bit clear")
	}
	cleared := flip(input, 3)
	if record.expectedBits != 9 || !record.follows(writer(cleared, 9)) {
		t.Fatalf("the unchanged emptied encoding does not follow: %x/%d", record.expected, record.expectedBits)
	}
	for _, position := range []int{0, 2, 3, 4, 8} {
		if record.follows(writer(flip(cleared, position), 9)) {
			t.Fatalf("an emptied change at bit %d still follows", position)
		}
	}
	bb := writer(cleared, 9)
	AppendTruncatedExtension(bb, FinalPadding{bits: &finalBits{truncated: record}})
	if !bytes.Equal(bb.CompleteBytes(), input) || bb.BitsWritten() != 8*len(input) {
		t.Fatalf("replay = %x (%d bits)", bb.CompleteBytes(), bb.BitsWritten())
	}
	// Inconsistent positions are refused rather than recorded.
	if _, err := kept.cutRecord(NewBitBufferFromBytes(input), input, 2, 15, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("a cut before the bitmap end = %v", err)
	}
	if _, err := (&ExtensionAdditions{start: 6, root: 5}).cutRecord(NewBitBufferFromBytes(input), input, 0, 20, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("a root ending before the extension bit = %v", err)
	}
}

// WithRecords carries a cut next to final padding without changing its shared
// table entry.
func TestWithRecordsKeepsTheCut(t *testing.T) {
	cut := &truncatedExtension{input: []byte{1}, kept: true}
	decoded := FinalPadding{}
	decoded = (&ExtensionAdditions{cut: cut}).Record(decoded)
	padding := finalPaddingOf(CompletePadding{bits: 1, count: 3})
	merged := padding.WithRecords(decoded)
	if !merged.Truncated() || merged.bits.truncated != cut {
		t.Fatalf("merged record %+v", merged.bits)
	}
	if bits, count := merged.Bits(); bits != 1 || count != 3 {
		t.Fatalf("merged padding %d/%d", bits, count)
	}
	if padding.Truncated() || paddingTable[paddingTableOffset[3]+1].truncated != nil {
		t.Fatal("the shared padding entry was modified")
	}
	if finalPaddingOf(CompletePadding{}).WithRecords(FinalPadding{}).Truncated() {
		t.Fatal("an empty record carries a cut")
	}
}
