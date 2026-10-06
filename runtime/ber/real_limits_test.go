package ber

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestRealDecimalDigitLimit(t *testing.T) {
	// X.690 (02/2021) §8.5.8 imposes no length ceiling. The optional
	// operational budget counts received digits, including leading zeros,
	// across both the mantissa and exponent, before bigint conversion.
	for _, tc := range []struct {
		name, contents string
		digits         int
	}{
		{"NR1", "\x017777", 4},
		{"NR2", "\x02-77,77", 4},
		{"NR3", "\x03  +77.7E+0", 4},
		{"exponent", "\x037.E+123", 4},
		{"leading zeros", "\x030007.E+000", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := []byte(tc.contents)
			wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
			if err != nil {
				t.Fatal(err)
			}
			for _, limit := range []int{0, tc.digits, tc.digits - 1} {
				option := WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: limit})
				_, valueErr := DecodeRealValue(contents, option)
				_, _, tlvErr := DecodeReal(wire, option)
				for _, got := range []error{valueErr, tlvErr} {
					if limit == tc.digits-1 {
						if !errors.Is(got, ErrResourceLimit) || errors.Is(got, ErrInvalidValue) {
							t.Fatalf("limit %d: %v", limit, got)
						}
					} else if got != nil {
						t.Fatalf("limit %d: %v", limit, got)
					}
				}
			}
		})
	}
}

func TestRealDecimalLimitPrecedesConversion(t *testing.T) {
	// The invalid exponent would be diagnosed during conversion. Hitting
	// the earlier digit budget must instead return the resource error.
	_, err := DecodeRealValue([]byte("\x037777.E+bad"), WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: 3}))
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("got %v", err)
	}
}

func TestRealDecimalLimitOptions(t *testing.T) {
	for _, value := range [][]byte{nil, {0x40}, {0x80, 0, 1}} {
		if _, err := DecodeRealValue(value, WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: 1})); err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRealValue(value, WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: -1})); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("negative limit: %v", err)
		}
	}
}

func FuzzRealDecimalDigitLimit(f *testing.F) {
	for _, value := range []string{"\x017777", "\x02-77.77", "\x037.E+123", "\x030007.E+000", "\x80\x00\x01"} {
		f.Add([]byte(value), uint8(3))
	}
	f.Fuzz(func(t *testing.T, value []byte, budget uint8) {
		limit := int(budget) + 1
		_, err := DecodeRealValue(value, WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: limit}))
		digits := 0
		if len(value) > 0 && value[0]&0xc0 == 0 {
			for _, octet := range value[1:] {
				if octet >= '0' && octet <= '9' {
					digits++
				}
			}
		}
		if errors.Is(err, ErrResourceLimit) != (digits > limit) {
			t.Fatalf("digits=%d limit=%d error=%v", digits, limit, err)
		}
	})
}
