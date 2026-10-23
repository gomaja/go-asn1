// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/integer_big_test.go; SHA-256 0a797e1223e26e5362bc8665a4e85d236f97ebb99398da66d3d3dbe1ba96cf1f.
package uper

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

func TestIntegerBigRootAndExtensionRoundTrip(t *testing.T) {
	t.Parallel()

	lower, upper := int64(-101), int64(100)
	values := []*big.Int{
		big.NewInt(-101),
		big.NewInt(100),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 521)),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(17)),
	}
	for _, aligned := range []bool{false} {
		_ = aligned
		for _, value := range values {
			value := new(big.Int).Set(value)
			name := map[bool]string{false: "uper"}[aligned] + "/" + value.String()
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				bb := NewBitBuffer()
				var err error

				{
					err = EncodeIntegerBig(bb, value, &lower, &upper, true)
				}
				if err != nil {
					t.Fatalf("encode: %v", err)
				}

				reader := NewBitBufferFromBytes(bb.Bytes())
				var got *big.Int

				{
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
			for _, aligned := range []bool{false} {
				_ = aligned
				bb := NewBitBuffer()
				var err error

				{
					err = EncodeInteger(bb, test.value, &test.lower, &test.upper, false)
				}
				if err != nil {
					t.Fatalf("aligned=%v encode: %v", aligned, err)
				}
				want := test.wantUPER

				if got := bb.Bytes(); !bytes.Equal(got, want) {
					t.Fatalf("aligned=%v encode = %x, want pycrate vector %x", aligned, got, want)
				}
				reader := NewBitBufferFromBytes(want)
				var decoded int64

				{
					decoded, err = DecodeInteger(reader, &test.lower, &test.upper, false)
				}
				if err != nil || decoded != test.value {
					t.Fatalf("aligned=%v decode = %d, %v; want %d", aligned, decoded, err, test.value)
				}
			}
		})
	}
}

func TestEncodeIntegerBigRejectsNilBeforeBufferMutation(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{false} {
		_ = aligned
		bb := NewBitBuffer()
		if err := bb.WriteBits(5, 3); err != nil {
			t.Fatal(err)
		}
		beforeBytes := append([]byte(nil), bb.Bytes()...)
		beforeBits := bb.BitsWritten()
		var err error

		{
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
	for _, aligned := range []bool{false} {
		_ = aligned
		bb := NewBitBuffer()
		var err error

		{
			err = EncodeIntegerBig(bb, big.NewInt(101), nil, &upper, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v encode error = %v, want ErrConstraintViolation", aligned, err)
		}

		wire := NewBitBuffer()

		{
			err = EncodeIntegerBig(wire, big.NewInt(101), nil, nil, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		reader := NewBitBufferFromBytes(wire.Bytes())

		{
			_, err = DecodeIntegerBig(reader, nil, &upper, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v decode error = %v, want ErrConstraintViolation", aligned, err)
		}
	}
}

func TestDecodeIntegerBigRejectsNonMinimalAndEmptyTwosComplement(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{false} {
		_ = aligned
		for _, wire := range [][]byte{
			{0x00},
			{0x02, 0x00, 0x7f},
			{0x02, 0xff, 0x80},
		} {
			reader := NewBitBufferFromBytes(wire)
			var err error

			{
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
	for _, aligned := range []bool{false} {
		_ = aligned
		bb := NewBitBuffer()
		if err := bb.WriteBits(5, 3); err != nil {
			t.Fatal(err)
		}
		var err error

		{
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

		{
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

		{
			err = EncodeIntegerBig(bb, value, nil, nil, false)
		}
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		reader := NewBitBufferFromBytes(bb.Bytes())
		var got *big.Int

		{
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

		{
			_, _ = DecodeIntegerBig(reader, nil, nil, false)
		}
	})
}
