package per

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestIntegerBigRootAndExtensionRoundTrip(t *testing.T) {
	t.Parallel()

	lower, upper := int64(-101), int64(100)
	values := []*big.Int{
		big.NewInt(-101),
		big.NewInt(100),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 521)),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(17)),
	}
	for _, aligned := range []bool{false, true} {
		for _, value := range values {
			value := new(big.Int).Set(value)
			name := map[bool]string{false: "uper", true: "aper"}[aligned] + "/" + value.String()
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				bb := NewBitBuffer()
				var err error
				if aligned {
					err = EncodeIntegerBigAligned(bb, value, &lower, &upper, true)
				} else {
					err = EncodeIntegerBig(bb, value, &lower, &upper, true)
				}
				if err != nil {
					t.Fatalf("encode: %v", err)
				}

				reader := NewBitBufferFromBytes(bb.Bytes())
				var got *big.Int
				if aligned {
					got, err = DecodeIntegerBigAligned(reader, &lower, &upper, true)
				} else {
					got, err = DecodeIntegerBig(reader, &lower, &upper, true)
				}
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				if got.Cmp(value) != 0 {
					t.Fatalf("decode = %s, want %s", got, value)
				}
			})
		}
	}
}

func TestIntegerValueSetBigRootGapAndExtension(t *testing.T) {
	t.Parallel()

	ranges := []IntegerRange{{Min: 1, Max: 3}, {Min: 5, Max: 5}}
	huge := new(big.Int).Lsh(big.NewInt(1), 521)
	for _, aligned := range []bool{false, true} {
		for _, value := range []*big.Int{big.NewInt(1), big.NewInt(5), huge} {
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeIntegerValueSetBigAligned(bb, value, ranges, true)
			} else {
				err = EncodeIntegerValueSetBig(bb, value, ranges, true)
			}
			if err != nil {
				t.Fatalf("aligned=%v encode %s: %v", aligned, value, err)
			}
			var got *big.Int
			if aligned {
				got, err = DecodeIntegerValueSetBigAligned(NewBitBufferFromBytes(bb.Bytes()), ranges, true)
			} else {
				got, err = DecodeIntegerValueSetBig(NewBitBufferFromBytes(bb.Bytes()), ranges, true)
			}
			if err != nil || got.Cmp(value) != 0 {
				t.Fatalf("aligned=%v decode = %v, %v; want %s", aligned, got, err, value)
			}
		}

		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeIntegerValueSetBigAligned(bb, big.NewInt(4), ranges, false)
		} else {
			err = EncodeIntegerValueSetBig(bb, big.NewInt(4), ranges, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v gap error = %v, want ErrConstraintViolation", aligned, err)
		}
	}
}

func TestIntegerBigUint64RootAndArbitraryExtension(t *testing.T) {
	t.Parallel()

	rootMaximum := new(big.Int).SetUint64(^uint64(0))
	positiveExtension := new(big.Int).Add(rootMaximum, big.NewInt(1))
	negativeExtension := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 130))
	for _, aligned := range []bool{false, true} {
		for _, value := range []*big.Int{rootMaximum, positiveExtension, negativeExtension} {
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeIntegerBigUint64RootAligned(bb, value, 0, ^uint64(0), true)
			} else {
				err = EncodeIntegerBigUint64Root(bb, value, 0, ^uint64(0), true)
			}
			if err != nil {
				t.Fatalf("aligned=%v encode %s: %v", aligned, value, err)
			}
			var got *big.Int
			if aligned {
				got, err = DecodeIntegerBigUint64RootAligned(NewBitBufferFromBytes(bb.Bytes()), 0, ^uint64(0), true)
			} else {
				got, err = DecodeIntegerBigUint64Root(NewBitBufferFromBytes(bb.Bytes()), 0, ^uint64(0), true)
			}
			if err != nil || got.Cmp(value) != 0 {
				t.Fatalf("aligned=%v decode = %v, %v; want %s", aligned, got, err, value)
			}
		}
	}
}

func TestIntegerBigArbitraryWidthRootBounds(t *testing.T) {
	t.Parallel()

	lower := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 130))
	upper := new(big.Int).Lsh(big.NewInt(1), 130)
	extension := new(big.Int).Lsh(big.NewInt(1), 260)
	for _, aligned := range []bool{false, true} {
		for _, value := range []*big.Int{lower, big.NewInt(0), upper, extension} {
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeIntegerBigBoundsAligned(bb, value, lower, upper, true)
			} else {
				err = EncodeIntegerBigBounds(bb, value, lower, upper, true)
			}
			if err != nil {
				t.Fatalf("aligned=%v encode %s: %v", aligned, value, err)
			}
			var got *big.Int
			if aligned {
				got, err = DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(bb.Bytes()), lower, upper, true)
			} else {
				got, err = DecodeIntegerBigBounds(NewBitBufferFromBytes(bb.Bytes()), lower, upper, true)
			}
			if err != nil || got.Cmp(value) != 0 {
				t.Fatalf("aligned=%v decode = %v, %v; want %s", aligned, got, err, value)
			}
		}
	}
}

func TestIntegerBigBoundsMatchInt64RootEncoding(t *testing.T) {
	t.Parallel()

	lower, upper := int64(-101), int64(100)
	for _, aligned := range []bool{false, true} {
		legacy := NewBitBuffer()
		wide := NewBitBuffer()
		var legacyErr, wideErr error
		if aligned {
			legacyErr = EncodeIntegerAligned(legacy, 17, &lower, &upper, false)
			wideErr = EncodeIntegerBigBoundsAligned(wide, big.NewInt(17), big.NewInt(lower), big.NewInt(upper), false)
		} else {
			legacyErr = EncodeInteger(legacy, 17, &lower, &upper, false)
			wideErr = EncodeIntegerBigBounds(wide, big.NewInt(17), big.NewInt(lower), big.NewInt(upper), false)
		}
		if legacyErr != nil || wideErr != nil || legacy.BitsWritten() != wide.BitsWritten() || !bytes.Equal(legacy.Bytes(), wide.Bytes()) {
			t.Fatalf("aligned=%v legacy=%x/%d/%v wide=%x/%d/%v", aligned, legacy.Bytes(), legacy.BitsWritten(), legacyErr, wide.Bytes(), wide.BitsWritten(), wideErr)
		}
	}
}

func TestIntegerConstraintPycrateVectors(t *testing.T) {
	t.Parallel()

	// Generated independently with pycrate 0.7.11 from:
	// Exact ::= INTEGER (-9007199254740992..100)
	// Stacked ::= INTEGER (0..100) (50..MAX)
	tests := []struct {
		name     string
		value    int64
		lower    int64
		upper    int64
		wantUPER []byte
		wantAPER []byte
	}{
		{name: "exact decimal bound", value: 0, lower: -9007199254740992, upper: 100, wantUPER: []byte{0x80, 0, 0, 0, 0, 0, 0}, wantAPER: []byte{0xc0, 0x20, 0, 0, 0, 0, 0, 0}},
		{name: "serial intersection", value: 75, lower: 50, upper: 100, wantUPER: []byte{0x64}, wantAPER: []byte{0x64}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, aligned := range []bool{false, true} {
				bb := NewBitBuffer()
				var err error
				if aligned {
					err = EncodeIntegerAligned(bb, test.value, &test.lower, &test.upper, false)
				} else {
					err = EncodeInteger(bb, test.value, &test.lower, &test.upper, false)
				}
				if err != nil {
					t.Fatalf("aligned=%v encode: %v", aligned, err)
				}
				want := test.wantUPER
				if aligned {
					want = test.wantAPER
				}
				if got := bb.Bytes(); !bytes.Equal(got, want) {
					t.Fatalf("aligned=%v encode = %x, want pycrate vector %x", aligned, got, want)
				}
				reader := NewBitBufferFromBytes(want)
				var decoded int64
				if aligned {
					decoded, err = DecodeIntegerAligned(reader, &test.lower, &test.upper, false)
				} else {
					decoded, err = DecodeInteger(reader, &test.lower, &test.upper, false)
				}
				if err != nil || decoded != test.value {
					t.Fatalf("aligned=%v decode = %d, %v; want %d", aligned, decoded, err, test.value)
				}
			}
		})
	}
}

func TestIntegerBigAlignedHugeRootUsesUnconstrainedLength(t *testing.T) {
	t.Parallel()

	lower := new(big.Int)
	upper := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 65536*8), big.NewInt(1))
	bb := NewBitBuffer()
	if err := EncodeIntegerBigBoundsAligned(bb, big.NewInt(1), lower, upper, false); err != nil {
		t.Fatalf("EncodeIntegerBigBoundsAligned() error = %v", err)
	}
	if got, want := bb.Bytes(), []byte{0x01, 0x01}; !bytes.Equal(got, want) {
		t.Fatalf("EncodeIntegerBigBoundsAligned() = %x, want unconstrained length and value %x", got, want)
	}
	decoded, err := DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes([]byte{0x01, 0x01}), lower, upper, false)
	if err != nil || decoded.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("DecodeIntegerBigBoundsAligned() = %v, %v; want 1", decoded, err)
	}
}

func TestEncodeIntegerBigRejectsNilBeforeBufferMutation(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{false, true} {
		bb := NewBitBuffer()
		if err := bb.WriteBits(5, 3); err != nil {
			t.Fatal(err)
		}
		beforeBytes := append([]byte(nil), bb.Bytes()...)
		beforeBits := bb.BitsWritten()
		var err error
		if aligned {
			err = EncodeIntegerBigAligned(bb, nil, nil, nil, false)
		} else {
			err = EncodeIntegerBig(bb, nil, nil, nil, false)
		}
		if !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("aligned=%v error = %v, want ErrInvalidValue", aligned, err)
		}
		if bb.BitsWritten() != beforeBits || !bytes.Equal(bb.Bytes(), beforeBytes) {
			t.Fatalf("aligned=%v mutated buffer: bits=%d bytes=%x", aligned, bb.BitsWritten(), bb.Bytes())
		}
	}
}

func TestIntegerBigEnforcesUpperOnlyConstraint(t *testing.T) {
	t.Parallel()

	upper := int64(100)
	for _, aligned := range []bool{false, true} {
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeIntegerBigAligned(bb, big.NewInt(101), nil, &upper, false)
		} else {
			err = EncodeIntegerBig(bb, big.NewInt(101), nil, &upper, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v encode error = %v, want ErrConstraintViolation", aligned, err)
		}

		wire := NewBitBuffer()
		if aligned {
			err = EncodeIntegerBigAligned(wire, big.NewInt(101), nil, nil, false)
		} else {
			err = EncodeIntegerBig(wire, big.NewInt(101), nil, nil, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		reader := NewBitBufferFromBytes(wire.Bytes())
		if aligned {
			_, err = DecodeIntegerBigAligned(reader, nil, &upper, false)
		} else {
			_, err = DecodeIntegerBig(reader, nil, &upper, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v decode error = %v, want ErrConstraintViolation", aligned, err)
		}
	}
}

func TestDecodeIntegerBigRejectsNonMinimalAndEmptyTwosComplement(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{false, true} {
		for _, wire := range [][]byte{
			{0x00},
			{0x02, 0x00, 0x7f},
			{0x02, 0xff, 0x80},
		} {
			reader := NewBitBufferFromBytes(wire)
			var err error
			if aligned {
				_, err = DecodeIntegerBigAligned(reader, nil, nil, false)
			} else {
				_, err = DecodeIntegerBig(reader, nil, nil, false)
			}
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("aligned=%v wire=%x error=%v, want ErrInvalidValue", aligned, wire, err)
			}
		}
	}
}

func TestIntegerBigFragmentedLengthRoundTrip(t *testing.T) {
	t.Parallel()

	value := new(big.Int).Lsh(big.NewInt(1), 8*16384)
	for _, aligned := range []bool{false, true} {
		bb := NewBitBuffer()
		if err := bb.WriteBits(5, 3); err != nil {
			t.Fatal(err)
		}
		var err error
		if aligned {
			err = EncodeIntegerBigAligned(bb, value, nil, nil, false)
		} else {
			err = EncodeIntegerBig(bb, value, nil, nil, false)
		}
		if err != nil {
			t.Fatalf("aligned=%v encode: %v", aligned, err)
		}

		reader := NewBitBufferFromBytes(bb.Bytes())
		if _, err := reader.ReadBits(3); err != nil {
			t.Fatal(err)
		}
		var got *big.Int
		if aligned {
			got, err = DecodeIntegerBigAligned(reader, nil, nil, false)
		} else {
			got, err = DecodeIntegerBig(reader, nil, nil, false)
		}
		if err != nil || got.Cmp(value) != 0 {
			t.Fatalf("aligned=%v decode=%v, %v", aligned, got, err)
		}
	}
}

func TestDecodeIntegerBigRejectsMalformedFragment(t *testing.T) {
	t.Parallel()

	for _, wire := range [][]byte{
		{0xc0},
		{0xc5},
		{0xc1, 0x01},
	} {
		if _, err := DecodeIntegerBig(NewBitBufferFromBytes(wire), nil, nil, false); err == nil {
			t.Fatalf("DecodeIntegerBig(%x) accepted malformed fragmented input", wire)
		}
	}
}

func TestDecodeIntegerBigRejectsNonMaximalFragmentSequence(t *testing.T) {
	t.Parallel()

	first := make([]byte, perFragmentUnit)
	first[0] = 1
	wire := append([]byte{0xc1}, first...)
	wire = append(wire, 0xc1)
	wire = append(wire, make([]byte, perFragmentUnit)...)
	wire = append(wire, 0x00)
	_, err := DecodeIntegerBig(NewBitBufferFromBytes(wire), nil, nil, false)
	if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "non-maximal") {
		t.Fatalf("DecodeIntegerBig() error = %v, want non-maximal fragment rejection", err)
	}
}

func FuzzIntegerBigRoundTrip(f *testing.F) {
	for _, seed := range []string{"0", "-1", "127", "128", "-128", "-129", "18446744073709551616", "-18446744073709551617"} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, decimal string, aligned bool) {
		value, ok := new(big.Int).SetString(decimal, 10)
		if !ok || len(decimal) > 2048 {
			t.Skip()
		}
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeIntegerBigAligned(bb, value, nil, nil, false)
		} else {
			err = EncodeIntegerBig(bb, value, nil, nil, false)
		}
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		reader := NewBitBufferFromBytes(bb.Bytes())
		var got *big.Int
		if aligned {
			got, err = DecodeIntegerBigAligned(reader, nil, nil, false)
		} else {
			got, err = DecodeIntegerBig(reader, nil, nil, false)
		}
		if err != nil || got.Cmp(value) != 0 {
			t.Fatalf("round trip %s: got %v, %v", value, got, err)
		}
	})
}

func FuzzDecodeIntegerBig(f *testing.F) {
	for _, seed := range [][]byte{
		{0x00},
		{0x01, 0x00},
		{0x02, 0x00, 0x7f},
		{0xc0},
		{0xc5},
		{0x80, 0x7f},
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, wire []byte, aligned bool) {
		if len(wire) > 1<<20 {
			t.Skip()
		}
		reader := NewBitBufferFromBytes(wire)
		if aligned {
			_, _ = DecodeIntegerBigAligned(reader, nil, nil, false)
		} else {
			_, _ = DecodeIntegerBig(reader, nil, nil, false)
		}
	})
}
