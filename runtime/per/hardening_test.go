package per

import (
	"bytes"
	"errors"
	"fmt"
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

func TestKnownMultiplierStringRejectsInvalidCharacterWidthBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		encode func(*BitBuffer, int) error
		decode func(*BitBuffer, int) error
	}{
		{
			name: "uper",
			encode: func(bb *BitBuffer, width int) error {
				return EncodeKnownMultiplierString(bb, "A", width, 1, 1, true)
			},
			decode: func(bb *BitBuffer, width int) error {
				_, err := DecodeKnownMultiplierString(bb, width, 1, 1, true)
				return err
			},
		},
		{
			name: "aper",
			encode: func(bb *BitBuffer, width int) error {
				return EncodeKnownMultiplierStringAligned(bb, "A", width, 1, 1, true)
			},
			decode: func(bb *BitBuffer, width int) error {
				_, err := DecodeKnownMultiplierStringAligned(bb, width, 1, 1, true)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, width := range []int{-1, 0, 33} {
				t.Run(fmt.Sprintf("width_%d", width), func(t *testing.T) {
					writer := NewBitBuffer()
					if err := writer.WriteBits(5, 3); err != nil {
						t.Fatal(err)
					}
					beforeBytes := append([]byte(nil), writer.Bytes()...)
					beforeBits := writer.BitsWritten()
					if err := tc.encode(writer, width); !errors.Is(err, ErrInvalidValue) {
						t.Fatalf("encode width %d error = %v, want ErrInvalidValue", width, err)
					}
					if !bytes.Equal(writer.Bytes(), beforeBytes) || writer.BitsWritten() != beforeBits {
						t.Fatalf("encoder mutated buffer for width %d", width)
					}

					reader := NewBitBufferFromBytes([]byte{0xff})
					beforeRead := reader.BitPos()
					if err := tc.decode(reader, width); !errors.Is(err, ErrInvalidValue) {
						t.Fatalf("decode width %d error = %v, want ErrInvalidValue", width, err)
					}
					if reader.BitPos() != beforeRead {
						t.Fatalf("decoder consumed %d bits for width %d", reader.BitPos()-beforeRead, width)
					}
				})
			}
		})
	}
}

func TestKnownMultiplierStringPreflightsPayloadBeforeAllocation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
		decode  func(*BitBuffer) error
	}{
		{
			name: "uper",
			decode: func(bb *BitBuffer) error {
				_, err := DecodeKnownMultiplierString(bb, 7, 0, 0, false)
				return err
			},
		},
		{
			name:    "aper",
			aligned: true,
			decode: func(bb *BitBuffer) error {
				_, err := DecodeKnownMultiplierStringAligned(bb, 7, 0, 0, false)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := NewBitBuffer()
			var err error
			if tc.aligned {
				err = EncodeUnconstrainedLengthAligned(writer, 2)
			} else {
				err = EncodeUnconstrainedLength(writer, 2)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteBit(1); err != nil {
				t.Fatal(err)
			}

			reader := NewBitBufferFromBytes(writer.Bytes())
			reader.bitLen = writer.BitsWritten()
			if err := tc.decode(reader); !errors.Is(err, ErrTruncated) {
				t.Fatalf("decode error = %v, want ErrTruncated", err)
			}
			if reader.BitPos() != 8 {
				t.Fatalf("decoder consumed payload bits: bit position = %d, want 8", reader.BitPos())
			}
		})
	}
}

func TestKnownMultiplierWideCharacterRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		encode func(*BitBuffer, string, int) error
		decode func(*BitBuffer, int) (string, error)
	}{
		{
			name: "uper",
			encode: func(bb *BitBuffer, value string, width int) error {
				return EncodeKnownMultiplierString(bb, value, width, 1, 1, true)
			},
			decode: func(bb *BitBuffer, width int) (string, error) {
				return DecodeKnownMultiplierString(bb, width, 1, 1, true)
			},
		},
		{
			name: "aper",
			encode: func(bb *BitBuffer, value string, width int) error {
				return EncodeKnownMultiplierStringAligned(bb, value, width, 1, 1, true)
			},
			decode: func(bb *BitBuffer, width int) (string, error) {
				return DecodeKnownMultiplierStringAligned(bb, width, 1, 1, true)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range []struct {
				text  string
				width int
			}{
				{text: "\u03bb", width: 16},
				{text: "\U0001f600", width: 32},
			} {
				bb := NewBitBuffer()
				if err := tc.encode(bb, value.text, value.width); err != nil {
					t.Fatal(err)
				}
				got, err := tc.decode(NewBitBufferFromBytes(bb.Bytes()), value.width)
				if err != nil {
					t.Fatal(err)
				}
				if got != value.text {
					t.Fatalf("round trip = %q, want %q", got, value.text)
				}
			}
		})
	}
}

func TestLargeRootSizeRejectsOutOfRangeValues(t *testing.T) {
	const (
		lower = int64(70000)
		upper = int64(70010)
	)
	for _, tc := range []struct {
		name          string
		encodeOutside func(*BitBuffer) error
		encodeRoot    func(*BitBuffer) error
		decodeRoot    func(*BitBuffer) error
	}{
		{
			name: "uper/bit-string",
			encodeOutside: func(bb *BitBuffer) error {
				return EncodeBitString(bb, []byte{0x80}, 1, lower, upper, true)
			},
			encodeRoot: func(bb *BitBuffer) error {
				if err := bb.WriteBit(0); err != nil {
					return err
				}
				if err := EncodeUnconstrainedLength(bb, 1); err != nil {
					return err
				}
				return bb.WriteBit(1)
			},
			decodeRoot: func(bb *BitBuffer) error {
				_, _, err := DecodeBitStringExt(bb, lower, upper, true, true)
				return err
			},
		},
		{
			name: "uper/octet-string",
			encodeOutside: func(bb *BitBuffer) error {
				return EncodeOctetString(bb, []byte{0x80}, lower, upper, true)
			},
			encodeRoot: func(bb *BitBuffer) error {
				if err := bb.WriteBit(0); err != nil {
					return err
				}
				if err := EncodeUnconstrainedLength(bb, 1); err != nil {
					return err
				}
				return bb.WriteBits(0x80, 8)
			},
			decodeRoot: func(bb *BitBuffer) error {
				_, err := DecodeOctetStringExt(bb, lower, upper, true, true)
				return err
			},
		},
		{
			name: "uper/character-string",
			encodeOutside: func(bb *BitBuffer) error {
				return EncodeKnownMultiplierString(bb, "A", 7, lower, upper, true)
			},
			encodeRoot: func(bb *BitBuffer) error {
				if err := bb.WriteBit(0); err != nil {
					return err
				}
				if err := EncodeUnconstrainedLength(bb, 1); err != nil {
					return err
				}
				return bb.WriteBits('A', 7)
			},
			decodeRoot: func(bb *BitBuffer) error {
				_, err := DecodeKnownMultiplierStringExt(bb, 7, lower, upper, true, true)
				return err
			},
		},
		{
			name: "aper/bit-string",
			encodeOutside: func(bb *BitBuffer) error {
				return EncodeBitStringAligned(bb, []byte{0x80}, 1, lower, upper, true)
			},
			encodeRoot: func(bb *BitBuffer) error {
				if err := bb.WriteBit(0); err != nil {
					return err
				}
				if err := EncodeUnconstrainedLengthAligned(bb, 1); err != nil {
					return err
				}
				bb.AlignToOctetWrite()
				return bb.WriteBit(1)
			},
			decodeRoot: func(bb *BitBuffer) error {
				_, _, err := DecodeBitStringAlignedExt(bb, lower, upper, true, true)
				return err
			},
		},
		{
			name: "aper/octet-string",
			encodeOutside: func(bb *BitBuffer) error {
				return EncodeOctetStringAligned(bb, []byte{0x80}, lower, upper, true)
			},
			encodeRoot: func(bb *BitBuffer) error {
				if err := bb.WriteBit(0); err != nil {
					return err
				}
				if err := EncodeUnconstrainedLengthAligned(bb, 1); err != nil {
					return err
				}
				return bb.WriteBits(0x80, 8)
			},
			decodeRoot: func(bb *BitBuffer) error {
				_, err := DecodeOctetStringAlignedExt(bb, lower, upper, true, true)
				return err
			},
		},
		{
			name: "aper/character-string",
			encodeOutside: func(bb *BitBuffer) error {
				return EncodeKnownMultiplierStringAligned(bb, "A", 7, lower, upper, true)
			},
			encodeRoot: func(bb *BitBuffer) error {
				if err := bb.WriteBit(0); err != nil {
					return err
				}
				if err := EncodeUnconstrainedLengthAligned(bb, 1); err != nil {
					return err
				}
				bb.AlignToOctetWrite()
				return bb.WriteBits('A', 7)
			},
			decodeRoot: func(bb *BitBuffer) error {
				_, err := DecodeKnownMultiplierStringAlignedExt(bb, 7, lower, upper, true, true)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.encodeOutside(NewBitBuffer()); !errors.Is(err, ErrConstraintViolation) {
				t.Fatalf("encode error = %v, want ErrConstraintViolation", err)
			}

			wire := NewBitBuffer()
			if err := tc.encodeRoot(wire); err != nil {
				t.Fatal(err)
			}
			if err := tc.decodeRoot(NewBitBufferFromBytes(wire.Bytes())); !errors.Is(err, ErrConstraintViolation) {
				t.Fatalf("decode error = %v, want ErrConstraintViolation", err)
			}
		})
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
