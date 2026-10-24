// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/s1ap_strict_fields_test.go; SHA-256 3fe6f7d75037f21047aa87519ba3065c0e1dcdb4a138dc25877e726101e3dd21.
package aper

import (
	"errors"
	"testing"
)

// X.691 (02/2021) §§13.1–13.2.2 enforce the source INTEGER root and its extension marker.
func TestS1APStrictIntegerLocations(t *testing.T) {
	cases := []struct {
		name, clause string
		wire         []byte
		decode       func(*BitBuffer) error
	}{
		{"uint unused root", "§13.2.2", []byte{0xc0}, func(bb *BitBuffer) error { _, err := DecodeIntegerUint64Aligned(bb, 0, 2, false); return err }},
		{"uint extension inside root", "§13.1", []byte{0x80, 1, 1}, func(bb *BitBuffer) error { _, err := DecodeIntegerUint64Aligned(bb, 0, 2, true); return err }},
		{"disjoint root gap", "§13.2.2", []byte{0x60}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerValueSetBigAligned(bb, []IntegerRange{{Min: 1, Max: 3}, {Min: 5, Max: 5}}, false)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, options := range [][]DecodeOption{nil, {WithReceiverMode()}} {
				state := ApplyDecodeOptions(options...)
				bb := NewBitBufferFromBytes(tc.wire)
				if err := bb.SetDecodeOptionsAligned(state); err != nil {
					t.Fatal(err)
				}
				report, err := FinishDecode(state, tc.decode(bb))
				var located *DecodeError
				if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != tc.clause || !located.Location.HasWireLocation || len(report.Deviations) != 1 {
					t.Fatalf("report=%+v error=%v located=%+v", report, err, located)
				}
			}
		})
	}
}

// X.691 (02/2021) §30.5.7 requires all declared characters to be present.
func TestS1APCharacterTruncationStaysBounded(t *testing.T) {
	alphabet := PermittedAlphabet{' ', ' ', '\'', ')', '+', ':', '=', '=', '?', '?', 'A', 'Z', 'a', 'z'}
	var first float64
	for _, length := range []int64{64, 128, 256, 512} {
		writer := NewBitBuffer()
		if err := EncodeUnconstrainedLengthAligned(writer, length); err != nil {
			t.Fatal(err)
		}
		wire := writer.CompleteBytes()
		decode := func() error {
			_, err := DecodeAlphabetStringAligned(NewBitBufferFromBytes(wire), alphabet, 0, 0, false, false)
			return err
		}
		err := decode()
		var located *DecodeError
		if !errors.Is(err, ErrSyntax) || !errors.Is(err, ErrTruncated) || !errors.As(err, &located) || located.Rule.Clause != "§30.5.7" || !located.Location.HasWireLocation {
			t.Fatalf("length=%d error=%v", length, err)
		}
		allocations := testing.AllocsPerRun(100, func() {
			if decode() == nil {
				panic("truncated string accepted")
			}
		})
		if allocations >= 8 {
			t.Fatalf("length=%d allocations=%v reached bound 8", length, allocations)
		}
		if first == 0 {
			first = allocations
		} else if allocations > first {
			t.Fatalf("truncation cost grew: %v to %v", first, allocations)
		}
		t.Logf("length=%d allocations=%v bound=8", length, allocations)
	}
}
