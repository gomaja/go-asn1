// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_int64_boundary_test.go; SHA-256 f0a56decb3c10a8eb08dd1d93ab84b35fec6d21f28dc4f758471530c9948ef8e.
package aper

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"testing"
)

// X.691 (02/2021) §11.8: an unconstrained INTEGER may exceed int64.
func TestUnconstrainedInt64Boundary(t *testing.T) {
	for _, aligned := range []bool{true} {
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
					err = encodeIntegerBigForTest(wire, tc.value, nil, nil, false)
				} else {
					err = encodeIntegerBigForTest(wire, tc.value, nil, nil, false)
				}
				if err != nil {
					t.Fatal(err)
				}
				reader := NewBitBufferFromBytes(wire.Bytes())
				var got int64
				if aligned {
					got, err = DecodeUnconstrainedWholeNumberAligned(reader)
				} else {
					got, err = DecodeUnconstrainedWholeNumberAligned(reader)
				}
				if !tc.fits {
					if !errors.Is(err, ErrLimit) {
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
					err = EncodeUnconstrainedWholeNumberAligned(reencoded, got)
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
	for _, aligned := range []bool{true} {
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
				err = encodeIntegerBigForTest(wire, tc.value, &low, &high, true)
			} else {
				err = encodeIntegerBigForTest(wire, tc.value, &low, &high, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			reader := NewBitBufferFromBytes(wire.Bytes())
			var got int64
			if aligned {
				got, err = DecodeIntegerAligned(reader, &low, &high, true)
			} else {
				got, err = DecodeIntegerAligned(reader, &low, &high, true)
			}
			if !tc.fits {
				if !errors.Is(err, ErrLimit) {
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
