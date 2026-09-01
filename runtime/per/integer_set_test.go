package per

import (
	"bytes"
	"errors"
	"testing"
)

func TestIntegerValueSetUPERRootAndExtension(t *testing.T) {
	t.Parallel()

	ranges := []IntegerRange{{Min: 1, Max: 3}, {Min: 5, Max: 5}}
	for _, value := range []int64{1, 3, 5} {
		bb := NewBitBuffer()
		if err := EncodeIntegerValueSet(bb, value, ranges, false); err != nil {
			t.Fatalf("EncodeIntegerValueSet(%d): %v", value, err)
		}
		got, err := DecodeIntegerValueSet(NewBitBufferFromBytes(bb.Bytes()), ranges, false)
		if err != nil || got != value {
			t.Fatalf("DecodeIntegerValueSet(%d) = %d, %v", value, got, err)
		}
	}
	if err := EncodeIntegerValueSet(NewBitBuffer(), 4, ranges, false); err == nil {
		t.Fatal("EncodeIntegerValueSet(4) accepted a non-extensible gap")
	}
	bb := NewBitBuffer()
	if err := EncodeIntegerValueSet(bb, 4, ranges, true); err != nil {
		t.Fatalf("EncodeIntegerValueSet(extension): %v", err)
	}
	got, err := DecodeIntegerValueSet(NewBitBufferFromBytes(bb.Bytes()), ranges, true)
	if err != nil || got != 4 {
		t.Fatalf("DecodeIntegerValueSet(extension) = %d, %v", got, err)
	}
}

func TestUint64IntegerPERBoundaries(t *testing.T) {
	t.Parallel()

	values := []uint64{0, 1, 1<<63 + 17, ^uint64(0)}
	for _, aligned := range []bool{false, true} {
		for _, value := range values {
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeIntegerUint64Aligned(bb, value, 0, ^uint64(0), false)
			} else {
				err = EncodeIntegerUint64(bb, value, 0, ^uint64(0), false)
			}
			if err != nil {
				t.Fatalf("encode aligned=%v value=%d: %v", aligned, value, err)
			}
			reader := NewBitBufferFromBytes(bb.Bytes())
			var got uint64
			if aligned {
				got, err = DecodeIntegerUint64Aligned(reader, 0, ^uint64(0), false)
			} else {
				got, err = DecodeIntegerUint64(reader, 0, ^uint64(0), false)
			}
			if err != nil || got != value {
				t.Fatalf("decode aligned=%v value=%d = %d, %v", aligned, value, got, err)
			}
		}
	}
}

func TestEncodeIntegerUint64RejectsInvertedRangeBeforeMutation(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		aligned    bool
		extensible bool
	}{
		{name: "uper/non-extensible"},
		{name: "uper/extensible", extensible: true},
		{name: "aper/non-extensible", aligned: true},
		{name: "aper/extensible", aligned: true, extensible: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bb := NewBitBuffer()
			if err := bb.WriteBits(0x5, 3); err != nil {
				t.Fatal(err)
			}
			beforeBytes := append([]byte(nil), bb.Bytes()...)
			beforeBits := bb.BitsWritten()

			var err error
			if test.aligned {
				err = EncodeIntegerUint64Aligned(bb, 7, 9, 3, test.extensible)
			} else {
				err = EncodeIntegerUint64(bb, 7, 9, 3, test.extensible)
			}
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("encode error = %v, want ErrInvalidValue", err)
			}
			if got := bb.Bytes(); !bytes.Equal(got, beforeBytes) {
				t.Fatalf("buffer bytes = %x, want unchanged %x", got, beforeBytes)
			}
			if got := bb.BitsWritten(); got != beforeBits {
				t.Fatalf("bits written = %d, want unchanged %d", got, beforeBits)
			}
		})
	}
}

func TestBitStringExtUPERRoundTrip(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		data   []byte
		bitLen int
	}{
		{name: "root", data: []byte{0xa0}, bitLen: 3},
		{name: "extension", data: []byte{0xab, 0xc0}, bitLen: 10},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bb := NewBitBuffer()
			if err := EncodeBitStringExt(bb, test.data, test.bitLen, 1, 8, true, true); err != nil {
				t.Fatalf("EncodeBitStringExt() error = %v", err)
			}
			gotData, gotBitLen, err := DecodeBitStringExt(NewBitBufferFromBytes(bb.Bytes()), 1, 8, true, true)
			if err != nil {
				t.Fatalf("DecodeBitStringExt() error = %v", err)
			}
			if gotBitLen != test.bitLen || !bytes.Equal(gotData, test.data) {
				t.Fatalf("DecodeBitStringExt() = %x/%d, want %x/%d", gotData, gotBitLen, test.data, test.bitLen)
			}
		})
	}
}

func TestSizeExtensibleOctetAndKnownMultiplierStringsRoundTrip(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{false, true} {
		aligned := aligned
		for _, extension := range []bool{false, true} {
			extension := extension
			t.Run(map[bool]string{false: "uper", true: "aper"}[aligned]+"/"+map[bool]string{false: "root", true: "extension"}[extension], func(t *testing.T) {
				t.Parallel()

				octets := []byte{0x12, 0x34}
				text := "AB"
				if extension {
					octets = []byte{0x12, 0x34, 0x56, 0x78, 0x9a}
					text = "ABCDE"
				}

				octetBits := NewBitBuffer()
				var err error
				if aligned {
					err = EncodeOctetStringAlignedExt(octetBits, octets, 1, 4, true, true)
				} else {
					err = EncodeOctetStringExt(octetBits, octets, 1, 4, true, true)
				}
				if err != nil {
					t.Fatalf("encode octets: %v", err)
				}
				var gotOctets []byte
				if aligned {
					gotOctets, err = DecodeOctetStringAlignedExt(NewBitBufferFromBytes(octetBits.Bytes()), 1, 4, true, true)
				} else {
					gotOctets, err = DecodeOctetStringExt(NewBitBufferFromBytes(octetBits.Bytes()), 1, 4, true, true)
				}
				if err != nil || !bytes.Equal(gotOctets, octets) {
					t.Fatalf("decode octets = %x, %v, want %x", gotOctets, err, octets)
				}

				stringBits := NewBitBuffer()
				if aligned {
					err = EncodeKnownMultiplierStringAlignedExt(stringBits, text, 7, 1, 4, true, true)
				} else {
					err = EncodeKnownMultiplierStringExt(stringBits, text, 7, 1, 4, true, true)
				}
				if err != nil {
					t.Fatalf("encode string: %v", err)
				}
				var gotText string
				if aligned {
					gotText, err = DecodeKnownMultiplierStringAlignedExt(NewBitBufferFromBytes(stringBits.Bytes()), 7, 1, 4, true, true)
				} else {
					gotText, err = DecodeKnownMultiplierStringExt(NewBitBufferFromBytes(stringBits.Bytes()), 7, 1, 4, true, true)
				}
				if err != nil || gotText != text {
					t.Fatalf("decode string = %q, %v, want %q", gotText, err, text)
				}
			})
		}
	}
}

func TestIntegerValueSetAPERRejectsDecodedGap(t *testing.T) {
	t.Parallel()

	ranges := []IntegerRange{{Min: 1, Max: 3}, {Min: 5, Max: 5}}
	bb := NewBitBuffer()
	if err := EncodeConstrainedWholeNumberAligned(bb, 4, 1, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerValueSetAligned(NewBitBufferFromBytes(bb.Bytes()), ranges, false); err == nil {
		t.Fatal("DecodeIntegerValueSetAligned accepted a root gap")
	}

	bb = NewBitBuffer()
	if err := EncodeIntegerValueSetAligned(bb, 4, ranges, true); err != nil {
		t.Fatalf("EncodeIntegerValueSetAligned(extension): %v", err)
	}
	got, err := DecodeIntegerValueSetAligned(NewBitBufferFromBytes(bb.Bytes()), ranges, true)
	if err != nil || got != 4 {
		t.Fatalf("DecodeIntegerValueSetAligned(extension) = %d, %v", got, err)
	}
}
