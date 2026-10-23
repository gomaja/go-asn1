// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/truncated_test.go; SHA-256 be14c5bbfec60dadd5da1ec262c49e34e1a453814eb9622ba8a049df4332518a.
package uper

import (
	"bytes"
	"errors"
	"testing"
)

// Ported from go-asn1 f2c57b4 runtime/per/truncated_test.go; UPER cases only.
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
func TestTruncatedExtensionOnlyAtTheEndOfTheOutermostInput(t *testing.T) {
	var log ToleranceLog
	options := DecodeOptions{TruncatedExtensionTolerance: &log}
	full := encodeHolder(t, fullHolder(), false)
	// The root ends at bit 4 and the bitmap at bit 14: a one-octet prefix
	// cuts the bitmap length, and so does the empty input the root.
	for _, cut := range [][]byte{full[:1], {}} {
		if _, err := decodeTop(cut, 2, false, options); !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut %x before the additions = %v, want ErrTruncated", cut, err)
		}
	}
	// Seven of ten octets end inside the second addition (bits 30 to 61).
	cut := full[:len(full)-3]
	// Nested: the same bytes carried in an open type that arrived in full.
	outer := NewBitBufferFromBytes(append([]byte{}, cut...))
	if err := outer.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	nested := NewBitBufferFromBytes(cut)
	nested.InheritDecodeOptions(outer)
	if _, err := decodeHolder(nested, 2, false); !errors.Is(err, ErrTruncated) {
		t.Fatalf("nested cut = %v, want ErrTruncated", err)
	}
	// Deferred BIT STRING contents arrived in full too.
	deferred := &Deferred{kind: BitStringContainer, raw: cut, bitLength: 8 * len(cut)}
	later, err := deferred.BitBuffer(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHolder(later, 2, false); !errors.Is(err, ErrTruncated) {
		t.Fatalf("deferred cut = %v, want ErrTruncated", err)
	}
	if records := log.Snapshot(); len(records) != 0 {
		t.Fatalf("failed decodes recorded %+v", records)
	}
	// TrailingBitsTolerance alone does not accept a cut.
	if _, err := decodeTop(cut, 2, false, DecodeOptions{TrailingBitsTolerance: &log}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("TrailingBitsTolerance accepted a cut: %v", err)
	}
}

// An invalid length determinant is reported, not taken for a cut.
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
