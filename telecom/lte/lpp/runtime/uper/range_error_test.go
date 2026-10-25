// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/range_error_test.go; SHA-256 beda9a7998ce80cea1ad22a344331515138ad05f03937f498dccecf6e08efaa0.
package uper

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The rejected value lb + offset and the bounds must share one domain. The
// first case is the TS 37.355 V19.3.0 §6.4.1 Polygon SIZE (3..15) length
// field 0b1101, which carries 16 points.

// Range 100005 needs three octets: a 2-bit length field (3 => 0b10),
// alignment, then offset 0x01ffff.

func TestCollectionRootErrorReportsSizeBounds(t *testing.T) {
	cases := []struct {
		size SizeConstraint
		want string
	}{
		{SizeConstraint{Lower: 5, HasLower: true, Upper: 70000, HasUpper: true}, "collection length 2 is outside its root SIZE(5..70000)"},
		{SizeConstraint{Lower: 5, HasLower: true}, "collection length 2 is outside its root SIZE(5..MAX)"},
	}
	for _, tc := range cases {
		bb := NewBitBuffer()
		if err := EncodeUnconstrainedLength(bb, 2); err != nil {
			t.Fatal(err)
		}
		_, err := DecodeCollection(NewBitBufferFromBytes(bb.Bytes()), tc.size, false, func(int64, int64) error { return nil })
		if !errors.Is(err, ErrConstraintViolation) || !strings.HasSuffix(err.Error(), ": "+tc.want) {
			t.Fatalf("error = %v, want %q", err, tc.want)
		}
	}
	if got := (SizeConstraint{Upper: 4, HasUpper: true, Extensible: true}).String(); got != "SIZE(0..4, ...)" {
		t.Fatalf("String() = %q", got)
	}
}

// Size, length and bound diagnostics report the rejected value with its
// bound. The fragmented case is two determinants: 0xc4 carries 4 x 16K = 65536
// elements and 0x01 one more, so the rejected total is 65537 (X.691 (02/2021)
// 11.9.3.8).

// A negative BIT STRING length is reported as such, not as an octet shortage,
// and a short source states required and available octets with units.

func TestBitCountRangeDiagnostics(t *testing.T) {
	for _, n := range []int{-1, 65} {
		if err := NewBitBuffer().WriteBits(0, n); !errors.Is(err, ErrInvalidValue) || !strings.HasSuffix(err.Error(), fmt.Sprintf(": WriteBits n=%d is outside [0..64]", n)) {
			t.Fatalf("WriteBits(%d) error = %v", n, err)
		}
		if _, err := NewBitBufferFromBytes(make([]byte, 16)).ReadBits(n); !errors.Is(err, ErrInvalidValue) || !strings.HasSuffix(err.Error(), fmt.Sprintf(": ReadBits n=%d is outside [0..64]", n)) {
			t.Fatalf("ReadBits(%d) error = %v", n, err)
		}
	}
}
