// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/minimal_integer_octets_test.go; SHA-256 00224dc38454220001ac29fddce645c54ab3ff341f7d08b3ea3288ad187d350d.
package aper

import (
	"errors"
	"math/big"
	"testing"
)

// ITU-T X.691 (02/2021) §§11.3.6, 11.5.7.4, 11.6.2, 11.7.4.
func TestMinimumUnsignedIntegerOctets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    []byte
		decode  func(*BitBuffer) (int64, error)
		wantErr bool
	}{
		{"aper-semi-leading-zero", []byte{0x02, 0x00, 0x40}, func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumberAligned(bb, 0) }, true},
		{"aper-semi-zero-length", []byte{0x00}, func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumberAligned(bb, 0) }, true},
		{"aper-semi-zero", []byte{0x01, 0x00}, func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumberAligned(bb, 0) }, false},
		{"aper-constrained-leading-zero", []byte{0x40, 0x00, 0x40}, func(bb *BitBuffer) (int64, error) { return DecodeConstrainedWholeNumberAligned(bb, 0, 0xffffff) }, true},
		{"aper-constrained-canonical", []byte{0x00, 0x40}, func(bb *BitBuffer) (int64, error) { return DecodeConstrainedWholeNumberAligned(bb, 0, 0xffffff) }, false},
		{"aper-small-index-leading-zero", []byte{0x80, 0x02, 0x00, 0x40}, DecodeNormallySmallNonNegativeAligned, true},
		{"aper-small-index-canonical", []byte{0x80, 0x01, 0x40}, DecodeNormallySmallNonNegativeAligned, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.decode(NewBitBufferFromBytes(tc.wire))
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("decode %x: got %d, error %v; want ErrInvalidValue", tc.wire, got, err)
				}
			} else if err != nil {
				t.Fatalf("decode %x: unexpected error %v", tc.wire, err)
			}
		})
	}
}

// The arbitrary-width integer decoder has its own octet reader. Keep the
// minimum-width checks covered there as well as in the int64 decoder.
// ITU-T X.691 (02/2021) §§11.3.6, 11.5.7.4, 11.7.4.
func TestBigIntegerMinimumUnsignedOctets(t *testing.T) {
	lower := big.NewInt(0)
	upper := big.NewInt(0xffffff)
	for _, tc := range []struct {
		name    string
		wire    []byte
		aligned bool
		upper   *big.Int
		wantErr bool
	}{
		{"aper-semi-leading-zero", []byte{0x02, 0x00, 0x40}, true, nil, true},
		{"aper-semi-zero-length", []byte{0x00}, true, nil, true},
		{"aper-semi-canonical", []byte{0x01, 0x40}, true, nil, false},
		{"aper-constrained-leading-zero", []byte{0x40, 0x00, 0x40}, true, upper, true},
		{"aper-constrained-canonical", []byte{0x00, 0x40}, true, upper, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.aligned {
				_, err = DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(tc.wire), lower, tc.upper, false)
			} else {
				_, err = DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(tc.wire), lower, tc.upper, false)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("decode %x: error %v, want ErrInvalidValue", tc.wire, err)
				}
			} else if err != nil {
				t.Fatalf("decode %x: unexpected error %v", tc.wire, err)
			}
		})
	}
}
