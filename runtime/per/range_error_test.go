package per

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"
)

// The rejected value lb + offset and the bounds must share one domain. The
// first case is the TS 37.355 V19.3.0 §6.4.1 Polygon SIZE (3..15) length
// field 0b1101, which carries 16 points.
func TestConstrainedRangeErrorsReportValueAndOffset(t *testing.T) {
	cases := []struct {
		name   string
		input  []byte
		decode func(*BitBuffer) error
		want   string
	}{
		{"UPER", []byte{0xd0}, func(bb *BitBuffer) error {
			_, err := DecodeConstrainedWholeNumber(bb, 3, 15)
			return err
		}, "value 16 (offset 13) exceeds range [3..15]"},
		{"UPER no int64 wrap", []byte{0xc0}, func(bb *BitBuffer) error {
			_, err := DecodeConstrainedWholeNumber(bb, math.MaxInt64-2, math.MaxInt64)
			return err
		}, "value 9223372036854775808 (offset 3) exceeds range [9223372036854775805..9223372036854775807]"},
		{"APER bit field", []byte{0xd0}, func(bb *BitBuffer) error {
			_, err := DecodeConstrainedWholeNumberAligned(bb, 3, 15)
			return err
		}, "value 16 (offset 13) exceeds range [3..15]"},
		{"APER two octets", []byte{0xff, 0xff}, func(bb *BitBuffer) error {
			_, err := DecodeConstrainedWholeNumberAligned(bb, -100, 60000)
			return err
		}, "value 65435 (offset 65535) exceeds range [-100..60000]"},
		// Range 100005 needs three octets: a 2-bit length field (3 => 0b10),
		// alignment, then offset 0x01ffff.
		{"APER length-prefixed", []byte{0x80, 0x01, 0xff, 0xff}, func(bb *BitBuffer) error {
			_, err := DecodeConstrainedWholeNumberAligned(bb, -5, 100000)
			return err
		}, "value 131066 (offset 131071) exceeds range [-5..100000]"},
		{"UPER uint64", []byte{0xc0}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerUint64(bb, 10, 12, false)
			return err
		}, "value 13 (offset 3) exceeds range [10..12]"},
		{"APER uint64", []byte{0xc0}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerUint64Aligned(bb, 10, 12, false)
			return err
		}, "value 13 (offset 3) exceeds range [10..12]"},
		{"UPER big", []byte{0xc0}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerBigBounds(bb, big.NewInt(-7), big.NewInt(-5), false)
			return err
		}, "value -4 (offset 3) exceeds range [-7..-5]"},
		{"APER big", []byte{0xc0}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerBigBoundsAligned(bb, big.NewInt(-7), big.NewInt(-5), false)
			return err
		}, "value -4 (offset 3) exceeds range [-7..-5]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.decode(NewBitBufferFromBytes(tc.input))
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
			if !strings.HasSuffix(err.Error(), ": "+tc.want) {
				t.Fatalf("error = %q, want suffix %q", err, tc.want)
			}
		})
	}
}

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
func TestLengthDiagnosticsReportRejectedValueAndBound(t *testing.T) {
	ignore := func(int64, int64) error { return nil }
	cases := []struct {
		name string
		run  func() error
		want error
		text string
	}{
		{"fragmented total above SIZE upper bound", func() error {
			_, err := DecodeCollection(NewBitBufferFromBytes([]byte{0xc4, 0x01}), SizeConstraint{Upper: 65536, HasUpper: true}, false, ignore)
			return err
		}, ErrConstraintViolation, "fragmented length 65537 exceeds upper bound 65536"},
		{"extension length inside root", func() error {
			_, err := DecodeCollection(NewBitBufferFromBytes([]byte{0x81, 0x00}), SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true, Extensible: true}, false, ignore)
			return err
		}, ErrInvalidValue, "extension collection length 2 is inside the root SIZE(1..4, ...)"},
		{"unconstrained uint64 length", func() error {
			_, err := DecodeIntegerUint64(NewBitBufferFromBytes([]byte{0x85, 0x00}), 0, 10, true)
			return err
		}, ErrInvalidValue, "uint64 INTEGER length 10 is outside [1..9]"},
		{"normally small length encode", func() error {
			return EncodeNormallySmallLength(NewBitBuffer(), 16384)
		}, ErrUnsupportedFragmentedNormallySmallLength, "length 16384 is not below 16384"},
		{"aligned normally small length encode", func() error {
			return EncodeNormallySmallLengthAligned(NewBitBuffer(), 20000)
		}, ErrUnsupportedFragmentedNormallySmallLength, "length 20000 is not below 16384"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if !errors.Is(err, tc.want) || !strings.HasSuffix(err.Error(), ": "+tc.text) {
				t.Fatalf("error = %v, want %v with %q", err, tc.want, tc.text)
			}
		})
	}
	if err := EncodeUnconstrainedLength(NewBitBuffer(), 16384); err == nil || err.Error() != "per: length 16384 is not below 16384 and requires fragmentation (not yet supported)" {
		t.Fatalf("unconstrained length error = %v", err)
	}
}

// A negative BIT STRING length is reported as such, not as an octet shortage,
// and a short source states required and available octets with units.
func TestBitStringLengthDiagnosticsSeparateCauses(t *testing.T) {
	encoders := map[string]func(*BitBuffer, []byte, int, int64, int64, bool) error{
		"UPER": EncodeBitString,
		"APER": EncodeBitStringAligned,
	}
	for name, encode := range encoders {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				data   []byte
				bitLen int
				text   string
			}{
				{nil, -1, "BIT STRING length: per: value out of range: negative bit length -1"},
				{[]byte{0xff}, 9, "per: value out of range: BIT STRING length 9 bits requires 2 octets, source has 1 octets"},
			} {
				err := encode(NewBitBuffer(), tc.data, tc.bitLen, 0, 0, false)
				if !errors.Is(err, ErrInvalidValue) || err.Error() != tc.text {
					t.Fatalf("bitLen %d: error = %v, want %q", tc.bitLen, err, tc.text)
				}
			}
		})
	}
	if _, err := NewBitBufferFromBits([]byte{0, 0, 0}, 9); !errors.Is(err, ErrInvalidValue) || !strings.HasSuffix(err.Error(), ": bit-string length 9 bits requires 2 octets, source has 3 octets") {
		t.Fatalf("NewBitBufferFromBits error = %v", err)
	}
	if err := NewBitBuffer().WriteBitsFromBytes([]byte{0}, 9); !errors.Is(err, ErrInvalidValue) || !strings.HasSuffix(err.Error(), ": WriteBitsFromBytes 9 bits requires 2 octets, source has 1 octets") {
		t.Fatalf("WriteBitsFromBytes error = %v", err)
	}
	if err := NewBitBuffer().WriteBitsFromBytes(nil, -3); !errors.Is(err, ErrInvalidValue) || err.Error() != "WriteBitsFromBytes: per: value out of range: negative bit length -3" {
		t.Fatalf("WriteBitsFromBytes negative error = %v", err)
	}
}

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
