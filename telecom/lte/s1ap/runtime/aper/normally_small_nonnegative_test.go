// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/normally_small_nonnegative_test.go; SHA-256 60287c3dcec61d3dda2fd2e463814ef746c16a350db383a7997b13945fc78096.
package aper

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
		{"aper-zero", true, []byte{0x80, 0x01, 0x00}},
		{"aper-sixty-three", true, []byte{0x80, 0x01, 0x3f}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes(tc.wire)
			var err error
			if tc.aligned {
				_, err = DecodeNormallySmallNonNegativeAligned(bb)
			} else {
				_, err = DecodeNormallySmallNonNegativeAligned(bb)
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
				got, err = DecodeNormallySmallNonNegativeAligned(bb)
			}
			if err != nil || got != tc.want {
				t.Fatalf("decode %x: got %d, error %v; want %d", tc.wire, got, err, tc.want)
			}
		})
	}
}
