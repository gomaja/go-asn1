// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_big_test.go; SHA-256 2583fc5c12ceeb99a34d3a9422edd159cadaf3f491f5fe970d098ee880d353c4.
package aper

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestBigBitHelpersRejectNegativeCount(t *testing.T) {
	writer := NewBitBuffer()
	if err := writeBigBits(writer, big.NewInt(1), -1); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("writeBigBits(-1) = %v, want ErrInvalidValue", err)
	}
	if writer.BitsWritten() != 0 {
		t.Fatalf("writeBigBits(-1) wrote %d bits", writer.BitsWritten())
	}
	if _, err := readBigBits(NewBitBufferFromBytes([]byte{0x80}), -1); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("readBigBits(-1) = %v, want ErrInvalidValue", err)
	}
}

func TestIntegerBigArbitraryWidthRootBounds(t *testing.T) {
	t.Parallel()

	lower := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 130))
	upper := new(big.Int).Lsh(big.NewInt(1), 130)
	extension := new(big.Int).Lsh(big.NewInt(1), 260)
	for _, aligned := range []bool{true} {
		for _, value := range []*big.Int{lower, big.NewInt(0), upper, extension} {
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeIntegerBigBoundsAligned(bb, value, lower, upper, true)
			} else {
				err = EncodeIntegerBigBoundsAligned(bb, value, lower, upper, true)
			}
			if err != nil {
				t.Fatalf("aligned=%v encode %s: %v", aligned, value, err)
			}
			var got *big.Int
			if aligned {
				got, err = DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(bb.Bytes()), lower, upper, true)
			} else {
				got, err = DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(bb.Bytes()), lower, upper, true)
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
	for _, aligned := range []bool{true} {
		legacy := NewBitBuffer()
		wide := NewBitBuffer()
		var legacyErr, wideErr error
		if aligned {
			legacyErr = EncodeIntegerAligned(legacy, 17, &lower, &upper, false)
			wideErr = EncodeIntegerBigBoundsAligned(wide, big.NewInt(17), big.NewInt(lower), big.NewInt(upper), false)
		} else {
			legacyErr = EncodeIntegerAligned(legacy, 17, &lower, &upper, false)
			wideErr = EncodeIntegerBigBoundsAligned(wide, big.NewInt(17), big.NewInt(lower), big.NewInt(upper), false)
		}
		if legacyErr != nil || wideErr != nil || legacy.BitsWritten() != wide.BitsWritten() || !bytes.Equal(legacy.Bytes(), wide.Bytes()) {
			t.Fatalf("aligned=%v legacy=%x/%d/%v wide=%x/%d/%v", aligned, legacy.Bytes(), legacy.BitsWritten(), legacyErr, wide.Bytes(), wide.BitsWritten(), wideErr)
		}
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

	for _, aligned := range []bool{true} {
		bb := NewBitBuffer()
		if err := bb.WriteBits(5, 3); err != nil {
			t.Fatal(err)
		}
		beforeBytes := append([]byte(nil), bb.Bytes()...)
		beforeBits := bb.BitsWritten()
		var err error
		if aligned {
			err = encodeIntegerBigForTest(bb, nil, nil, nil, false)
		} else {
			err = encodeIntegerBigForTest(bb, nil, nil, nil, false)
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
	for _, aligned := range []bool{true} {
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = encodeIntegerBigForTest(bb, big.NewInt(101), nil, &upper, false)
		} else {
			err = encodeIntegerBigForTest(bb, big.NewInt(101), nil, &upper, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v encode error = %v, want ErrConstraintViolation", aligned, err)
		}

		wire := NewBitBuffer()
		if aligned {
			err = encodeIntegerBigForTest(wire, big.NewInt(101), nil, nil, false)
		} else {
			err = encodeIntegerBigForTest(wire, big.NewInt(101), nil, nil, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		reader := NewBitBufferFromBytes(wire.Bytes())
		if aligned {
			_, err = decodeIntegerBigForTest(reader, nil, &upper, false)
		} else {
			_, err = decodeIntegerBigForTest(reader, nil, &upper, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v decode error = %v, want ErrConstraintViolation", aligned, err)
		}
	}
}

func TestDecodeIntegerBigRejectsNonMinimalAndEmptyTwosComplement(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{true} {
		for _, wire := range [][]byte{
			{0x00},
			{0x02, 0x00, 0x7f},
			{0x02, 0xff, 0x80},
		} {
			reader := NewBitBufferFromBytes(wire)
			var err error
			if aligned {
				_, err = decodeIntegerBigForTest(reader, nil, nil, false)
			} else {
				_, err = decodeIntegerBigForTest(reader, nil, nil, false)
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
	for _, aligned := range []bool{true} {
		bb := NewBitBuffer()
		if err := bb.WriteBits(5, 3); err != nil {
			t.Fatal(err)
		}
		var err error
		if aligned {
			err = encodeIntegerBigForTest(bb, value, nil, nil, false)
		} else {
			err = encodeIntegerBigForTest(bb, value, nil, nil, false)
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
			got, err = decodeIntegerBigForTest(reader, nil, nil, false)
		} else {
			got, err = decodeIntegerBigForTest(reader, nil, nil, false)
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
		if _, err := decodeIntegerBigForTest(NewBitBufferFromBytes(wire), nil, nil, false); err == nil {
			t.Fatalf("decodeIntegerBigForTest(%x) accepted malformed fragmented input", wire)
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
	_, err := decodeIntegerBigForTest(NewBitBufferFromBytes(wire), nil, nil, false)
	if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "non-maximal") {
		t.Fatalf("decodeIntegerBigForTest() error = %v, want non-maximal fragment rejection", err)
	}
}
