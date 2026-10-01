package per

import (
	"errors"
	"testing"
)

// ITU-T X.691 (02/2021) §11.6.1-11.6.2 reserves the long form for n >= 64.
func TestNormallySmallNonNegativeRejectsLongFormBelow64(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
		wire    []byte
	}{
		{"uper-zero", false, []byte{0x80, 0x80, 0x00}},
		{"uper-sixty-three", false, []byte{0x80, 0x9f, 0x80}},
		{"aper-zero", true, []byte{0x80, 0x01, 0x00}},
		{"aper-sixty-three", true, []byte{0x80, 0x01, 0x3f}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes(tc.wire)
			var err error
			if tc.aligned {
				_, err = DecodeNormallySmallNonNegativeAligned(bb)
			} else {
				_, err = DecodeNormallySmallNonNegative(bb)
			}
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("decode %x: error = %v, want ErrInvalidValue", tc.wire, err)
			}
		})
	}
}

func TestNormallySmallNonNegativeAcceptsFormBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
		wire    []byte
		want    int64
	}{
		{"uper-short-zero", false, []byte{0x00}, 0},
		{"uper-short-sixty-three", false, []byte{0x7e}, 63},
		{"uper-long-sixty-four", false, []byte{0x80, 0xa0, 0x00}, 64},
		{"aper-short-zero", true, []byte{0x00}, 0},
		{"aper-short-sixty-three", true, []byte{0x7e}, 63},
		{"aper-long-sixty-four", true, []byte{0x80, 0x01, 0x40}, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes(tc.wire)
			var got int64
			var err error
			if tc.aligned {
				got, err = DecodeNormallySmallNonNegativeAligned(bb)
			} else {
				got, err = DecodeNormallySmallNonNegative(bb)
			}
			if err != nil || got != tc.want {
				t.Fatalf("decode %x: got %d, error %v; want %d", tc.wire, got, err, tc.want)
			}
		})
	}
}
