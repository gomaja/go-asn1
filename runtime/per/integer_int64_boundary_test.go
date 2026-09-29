package per

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"testing"
)

// X.691 (02/2021) §11.8: an unconstrained INTEGER may exceed int64.
func TestUnconstrainedInt64Boundary(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		for _, tc := range []struct {
			name  string
			value *big.Int
			fits  bool
		}{
			{"minimum", big.NewInt(math.MinInt64), true},
			{"maximum", big.NewInt(math.MaxInt64), true},
			{"positive overflow", new(big.Int).Lsh(big.NewInt(1), 63), false},
			{"negative overflow", new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1)), false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wire := NewBitBuffer()
				var err error
				if aligned {
					err = EncodeIntegerBigAligned(wire, tc.value, nil, nil, false)
				} else {
					err = EncodeIntegerBig(wire, tc.value, nil, nil, false)
				}
				if err != nil {
					t.Fatal(err)
				}
				reader := NewBitBufferFromBytes(wire.Bytes())
				var got int64
				if aligned {
					got, err = DecodeUnconstrainedWholeNumberAligned(reader)
				} else {
					got, err = DecodeUnconstrainedWholeNumber(reader)
				}
				if !tc.fits {
					if !errors.Is(err, ErrInvalidValue) {
						t.Fatalf("out-of-range %s decoded as %d, error %v", tc.value, got, err)
					}
					return
				}
				if err != nil || got != tc.value.Int64() {
					t.Fatalf("decoded=%d error=%v want=%s", got, err, tc.value)
				}
				reencoded := NewBitBuffer()
				if aligned {
					err = EncodeUnconstrainedWholeNumberAligned(reencoded, got)
				} else {
					err = EncodeUnconstrainedWholeNumber(reencoded, got)
				}
				if err != nil || !bytes.Equal(wire.Bytes(), reencoded.Bytes()) {
					t.Fatalf("round trip %x -> %x: %v", wire.Bytes(), reencoded.Bytes(), err)
				}
			})
		}
	}
}

func TestExtensionInt64Boundary(t *testing.T) {
	low, high := int64(0), int64(1)
	for _, aligned := range []bool{false, true} {
		for _, tc := range []struct {
			value *big.Int
			fits  bool
		}{
			{big.NewInt(math.MinInt64), true},
			{big.NewInt(math.MaxInt64), true},
			{new(big.Int).Lsh(big.NewInt(1), 63), false},
			{new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1)), false},
		} {
			wire := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeIntegerBigAligned(wire, tc.value, &low, &high, true)
			} else {
				err = EncodeIntegerBig(wire, tc.value, &low, &high, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			reader := NewBitBufferFromBytes(wire.Bytes())
			var got int64
			if aligned {
				got, err = DecodeIntegerAligned(reader, &low, &high, true)
			} else {
				got, err = DecodeInteger(reader, &low, &high, true)
			}
			if !tc.fits {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("extension %s decoded as %d, error %v", tc.value, got, err)
				}
				continue
			}
			if err != nil || got != tc.value.Int64() {
				t.Fatalf("extension decoded=%d error=%v want=%s", got, err, tc.value)
			}
		}
	}
}

func FuzzUnconstrainedInt64MatchesBigInteger(f *testing.F) {
	for _, wire := range [][]byte{
		{0x01, 0x00},
		{0x08, 0x80, 0, 0, 0, 0, 0, 0, 0},
		{0x09, 0, 0x80, 0, 0, 0, 0, 0, 0, 0},
		{0x09, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		for _, aligned := range []bool{false, true} {
			bigValue, bigErr := decodeBigTwosComplement(NewBitBufferFromBytes(wire), aligned)
			if bigErr != nil {
				continue
			}
			var got int64
			var err error
			if aligned {
				got, err = DecodeUnconstrainedWholeNumberAligned(NewBitBufferFromBytes(wire))
			} else {
				got, err = DecodeUnconstrainedWholeNumber(NewBitBufferFromBytes(wire))
			}
			if !bigValue.IsInt64() {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("%x decoded out-of-range %s as %d: %v", wire, bigValue, got, err)
				}
			} else if err != nil || got != bigValue.Int64() {
				t.Fatalf("%x decoded %d: %v, want %s", wire, got, err, bigValue)
			}
		}
	})
}
