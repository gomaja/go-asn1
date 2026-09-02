package per

import (
	"errors"
	"math"
	"testing"
)

func TestNormallySmallNonNegativeRejectsInt64Overflow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
	}{
		{name: "uper"},
		{name: "aper", aligned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := bb.WriteBit(1); err != nil {
				t.Fatal(err)
			}
			if tc.aligned {
				bb.AlignToOctetWrite()
			}
			if err := bb.WriteBits(8, 8); err != nil {
				t.Fatal(err)
			}
			if err := bb.WriteBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err != nil {
				t.Fatal(err)
			}

			input := NewBitBufferFromBytes(bb.Bytes())
			var err error
			if tc.aligned {
				_, err = DecodeNormallySmallNonNegativeAligned(input)
			} else {
				_, err = DecodeNormallySmallNonNegative(input)
			}
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("overflow error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

func TestAddNonNegativeOffsetInt64Boundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lb     int64
		offset uint64
		want   int64
	}{
		{name: "minimum unchanged", lb: math.MinInt64, want: math.MinInt64},
		{name: "minimum plus full width", lb: math.MinInt64, offset: ^uint64(0), want: math.MaxInt64},
		{name: "negative crosses zero", lb: -10, offset: 10, want: 0},
		{name: "negative reaches maximum", lb: -10, offset: uint64(math.MaxInt64) + 10, want: math.MaxInt64},
		{name: "zero reaches maximum", offset: math.MaxInt64, want: math.MaxInt64},
		{name: "maximum unchanged", lb: math.MaxInt64, want: math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := addNonNegativeOffset(tc.lb, tc.offset)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("addNonNegativeOffset(%d, %d) = %d, want %d", tc.lb, tc.offset, got, tc.want)
			}
		})
	}
}

func TestAddNonNegativeOffsetRejectsOverflow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lb     int64
		offset uint64
	}{
		{name: "negative lower bound", lb: -10, offset: uint64(math.MaxInt64) + 11},
		{name: "zero lower bound", offset: uint64(math.MaxInt64) + 1},
		{name: "maximum lower bound", lb: math.MaxInt64, offset: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := addNonNegativeOffset(tc.lb, tc.offset); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("overflow error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

func TestBitBufferRejectsImpossibleReadsBeforeAllocation(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0})
	if _, err := bb.ReadBytes(math.MaxInt); !errors.Is(err, ErrTruncated) {
		t.Fatalf("ReadBytes error = %v, want ErrTruncated", err)
	}
	if _, err := bb.ReadBitsToBytes(math.MaxInt); !errors.Is(err, ErrTruncated) {
		t.Fatalf("ReadBitsToBytes error = %v, want ErrTruncated", err)
	}
}

func TestConstrainedSizeRejectsNegativeBoundsBeforeBufferAccess(t *testing.T) {
	tests := []struct {
		name string
		run  func(*BitBuffer) error
	}{
		{name: "UPER encode bit string", run: func(bb *BitBuffer) error { return EncodeBitString(bb, nil, 0, -1, 1, true) }},
		{name: "UPER decode bit string", run: func(bb *BitBuffer) error { _, _, err := DecodeBitString(bb, -1, 1, true); return err }},
		{name: "UPER encode octet string", run: func(bb *BitBuffer) error { return EncodeOctetString(bb, nil, -1, 1, true) }},
		{name: "UPER decode octet string", run: func(bb *BitBuffer) error { _, err := DecodeOctetString(bb, -1, 1, true); return err }},
		{name: "UPER encode known multiplier string", run: func(bb *BitBuffer) error { return EncodeKnownMultiplierString(bb, "", 7, -1, 1, true) }},
		{name: "UPER decode known multiplier string", run: func(bb *BitBuffer) error { _, err := DecodeKnownMultiplierString(bb, 7, -1, 1, true); return err }},
		{name: "APER encode bit string", run: func(bb *BitBuffer) error { return EncodeBitStringAligned(bb, nil, 0, -1, 1, true) }},
		{name: "APER decode bit string", run: func(bb *BitBuffer) error { _, _, err := DecodeBitStringAligned(bb, -1, 1, true); return err }},
		{name: "APER encode octet string", run: func(bb *BitBuffer) error { return EncodeOctetStringAligned(bb, nil, -1, 1, true) }},
		{name: "APER decode octet string", run: func(bb *BitBuffer) error { _, err := DecodeOctetStringAligned(bb, -1, 1, true); return err }},
		{name: "APER encode known multiplier string", run: func(bb *BitBuffer) error { return EncodeKnownMultiplierStringAligned(bb, "", 7, -1, 1, true) }},
		{name: "APER decode known multiplier string", run: func(bb *BitBuffer) error {
			_, err := DecodeKnownMultiplierStringAligned(bb, 7, -1, 1, true)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{0xff})
			before := bb.bitPos
			if err := test.run(bb); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
			if bb.bitPos != before {
				t.Fatalf("buffer position = %d, want unchanged %d", bb.bitPos, before)
			}
		})
	}
}

func TestDecodeExtensionBitmapRejectsCountBeyondInput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
	}{
		{name: "uper"},
		{name: "aper", aligned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if tc.aligned {
				if err := EncodeNormallySmallNonNegativeAligned(bb, 1<<30); err != nil {
					t.Fatal(err)
				}
			} else if err := EncodeNormallySmallNonNegative(bb, 1<<30); err != nil {
				t.Fatal(err)
			}

			input := NewBitBufferFromBytes(bb.Bytes())
			var err error
			if tc.aligned {
				_, _, err = DecodeExtensionBitmapAligned(input)
			} else {
				_, _, err = DecodeExtensionBitmap(input)
			}
			if !errors.Is(err, ErrTruncated) {
				t.Fatalf("extension bitmap error = %v, want ErrTruncated", err)
			}
		})
	}
}

func TestDecodeExtensionBitmapRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
	}{
		{name: "uper"},
		{name: "aper", aligned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if tc.aligned {
				if err := EncodeNormallySmallNonNegativeAligned(bb, 2); err != nil {
					t.Fatal(err)
				}
			} else if err := EncodeNormallySmallNonNegative(bb, 2); err != nil {
				t.Fatal(err)
			}
			for _, present := range []bool{true, false, true} {
				if err := EncodeBoolean(bb, present); err != nil {
					t.Fatal(err)
				}
			}

			input := NewBitBufferFromBytes(bb.Bytes())
			var (
				count   int64
				present []bool
				err     error
			)
			if tc.aligned {
				count, present, err = DecodeExtensionBitmapAligned(input)
			} else {
				count, present, err = DecodeExtensionBitmap(input)
			}
			if err != nil {
				t.Fatal(err)
			}
			if count != 2 || len(present) != 3 || !present[0] || present[1] || !present[2] {
				t.Fatalf("extension bitmap = count %d, present %v", count, present)
			}
		})
	}
}

func FuzzDecodeExtensionBitmapNoPanic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0x80, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, decode := range []func(*BitBuffer) (int64, []bool, error){
			DecodeExtensionBitmap,
			DecodeExtensionBitmapAligned,
		} {
			count, present, err := decode(NewBitBufferFromBytes(raw))
			if err != nil {
				continue
			}
			if count < 0 || int64(len(present)) != count+1 {
				t.Fatalf("decoded extension bitmap = count %d, length %d", count, len(present))
			}
		}
	})
}
