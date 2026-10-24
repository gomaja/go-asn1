// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/truncated_test.go; SHA-256 eefbc6cd3be92bd896208d1f94afc811fdc8c37122fa89cc135c3cb12ac20570.
package uper

import (
	"bytes"
	"errors"
	"testing"
)

type holder struct {
	lead    []uint8
	flag    bool
	count   int64
	present []bool
	data    [][]byte
	final   FinalPadding
}

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
		length := EncodeNormallySmallLength

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
			encode := EncodeOpenType

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
		decodeBitmap := additions.DecodeBitmap

		count, present, err := decodeBitmap(bb)
		if err != nil {
			return nil, err
		}
		h.count, h.present, h.data = count, present, make([][]byte, count+1)
		for i := int64(0); i <= count; i++ {
			if present[i] && additions.Received(bb, i) {
				decode := DecodeOpenType

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

func decodeTop(data []byte, leadBits int, aligned bool, options DecodeOptions) (*holder, error) {
	bb := NewBitBufferFromBytes(data)

	if err := bb.SetDecodeOptions(options); err != nil {
		return nil, err
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

func TestTruncatedExtensionCutInContents(t *testing.T) {
	for _, aligned := range []bool{false} {
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
		if _, err := decodeTop(cut, 2, aligned, DecodeOptions{}); !errors.Is(err, ErrTruncated) {
			t.Fatalf("aligned=%v: strict decode of a cut addition = %v, want ErrTruncated", aligned, err)
		}
		h, err := decodeTop(cut, 2, aligned, DecodeOptions{TruncatedExtensionTolerance: &log})
		if err != nil {
			t.Fatalf("aligned=%v: tolerant decode: %v", aligned, err)
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
		strict, err := decodeTop(edited, 2, aligned, DecodeOptions{})
		if err != nil || strict.flag || strict.count != 2 || !equalBools(strict.present, []bool{true, false, false}) || !bytes.Equal(strict.data[0], []byte{0x5a}) {
			t.Fatalf("aligned=%v: edited value %x decodes to %+v, %v", aligned, edited, strict, err)
		}
	}
}

// bitsFrom returns the bits of data from offset to its end, MSB first.

func TestTruncatedExtensionCutInLengthDeterminant(t *testing.T) {
	long := fullHolder()
	long.data[1] = bytes.Repeat([]byte{0xc3}, 200) // two-octet length 0x80c8
	for _, aligned := range []bool{false} {
		full, starts := encodeHolderAt(t, long, aligned)
		offset := starts[1]
		// The first cut leaves two bits of the length determinant (none in
		// APER, where the open type starts on an octet), the second one more
		// octet, still short of the two-octet determinant 80c8.
		for _, cutAt := range []int{(offset + 7) / 8, (offset+7)/8 + 1} {
			cut := full[:cutAt]
			var log ToleranceLog
			h, err := decodeTop(cut, 2, aligned, DecodeOptions{TruncatedExtensionTolerance: &log})
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
	for _, aligned := range []bool{false} {
		value := &holder{lead: []uint8{0, 1, 1}, flag: true, count: 2, present: []bool{false, true, true}, data: [][]byte{nil, {0x01, 0x02}, {0x03}}}
		full := encodeHolder(t, value, aligned)
		cut := full[:len(full)-3]
		var log ToleranceLog
		h, err := decodeTop(cut, 3, aligned, DecodeOptions{TruncatedExtensionTolerance: &log})
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

// Errors stay errors: a cut in the root or the extension bitmap, and a cut
// open type in a buffer that does not read the outermost input.

func TestTruncatedExtensionInvalidDeterminantIsAnError(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0x80, 0x05}) // non-minimal two-octet length 5
	if err := bb.SetDecodeOptions(DecodeOptions{TruncatedExtensionTolerance: &ToleranceLog{}}); err != nil {
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

// The strict path keeps its allocations: the extension state adds none.

func TestTruncatedExtensionStrictPathAllocations(t *testing.T) {
	full := encodeHolder(t, fullHolder(), false)
	baseline := testing.AllocsPerRun(100, func() {
		bb := NewBitBufferFromBytes(full)
		bb.bitPos = 4
		count, present, err := DecodeExtensionBitmap(bb)
		if err != nil || count != 2 || !present[1] {
			t.Fatal(err)
		}
	})
	tracked := testing.AllocsPerRun(100, func() {
		bb := NewBitBufferFromBytes(full)
		bb.bitPos = 2
		additions := BeginExtensionAdditions(bb)
		bb.bitPos = 4
		count, present, err := additions.DecodeBitmap(bb)
		if err != nil || count != 2 || !present[1] || !additions.Received(bb, 0) || additions.Emptied() {
			t.Fatal(err)
		}
		if additions.Record(FinalPadding{}).Truncated() {
			t.Fatal("strict decode recorded a cut")
		}
		AppendTruncatedExtension(bb, FinalPadding{})
	})
	if tracked != baseline {
		t.Fatalf("strict extension decode allocates %v, want %v", tracked, baseline)
	}
}

// Records reach the log of the option that accepted them.

func TestTruncatedExtensionLogRouting(t *testing.T) {
	cut := encodeHolder(t, fullHolder(), false)
	cut = cut[:len(cut)-2]
	var shared, trailing, truncated ToleranceLog
	if _, err := decodeTop(cut, 2, false, DecodeOptions{TrailingBitsTolerance: &shared, TruncatedExtensionTolerance: &shared}); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTop(cut, 2, false, DecodeOptions{TrailingBitsTolerance: &trailing, TruncatedExtensionTolerance: &truncated}); err != nil {
		t.Fatal(err)
	}
	if len(shared.Snapshot()) != 1 || len(trailing.Snapshot()) != 0 || len(truncated.Snapshot()) != 1 {
		t.Fatalf("shared %+v, trailing %+v, truncated %+v", shared.Snapshot(), trailing.Snapshot(), truncated.Snapshot())
	}
	bb := NewBitBufferFromBytes(nil)
	if err := bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &trailing, TruncatedExtensionTolerance: &truncated}); err != nil {
		t.Fatal(err)
	}
	bb.publishTolerances([]Tolerance{{Kind: ToleratedTrailingBits}, {Kind: ToleratedTruncatedExtension}})
	if got := trailing.Snapshot(); len(got) != 1 || got[0].Kind != ToleratedTrailingBits {
		t.Fatalf("trailing log %+v", got)
	}
	if got := truncated.Snapshot(); len(got) != 2 || got[1].Kind != ToleratedTruncatedExtension {
		t.Fatalf("truncated log %+v", got)
	}
}
