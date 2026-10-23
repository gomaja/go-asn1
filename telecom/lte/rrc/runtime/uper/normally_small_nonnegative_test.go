// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/normally_small_nonnegative_test.go; SHA-256 be2b48da59b7addcc3ba08b5669f8cefe0e765fcdb2e4260caf78f3319eb3fd8.
package uper

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
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes(tc.wire)
			var err error

			{
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes(tc.wire)
			var got int64
			var err error

			{
				got, err = DecodeNormallySmallNonNegative(bb)
			}
			if err != nil || got != tc.want {
				t.Fatalf("decode %x: got %d, error %v; want %d", tc.wire, got, err, tc.want)
			}
		})
	}
}
