// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/padding_reservation_test.go; SHA-256 aa2b37eccf259454a394dacda2dccd0cb6b1a5a3e6a35616afa673988d2b78ee.
package aper

import (
	"errors"
	"strconv"
	"testing"
)

// The operation charge is pinned independently of the trace's implementation
// layout, including on 32-bit receivers.
func TestTerminalPaddingTraceReservation(t *testing.T) {
	var traceBytes uint64 = 80
	if strconv.IntSize == 32 {
		traceBytes = 40
	}
	for _, receiver := range []bool{false, true} {
		for _, padding := range []bool{false, true} {
			var options []DecodeOption
			if receiver {
				options = append(options, WithReceiverMode())
			}
			if padding {
				options = append(options, WithNonzeroTerminalPadding())
			}
			state := ApplyDecodeOptions(options...)
			before := state.Usage().AllocatedBytes
			bb := NewBitBufferFromBytes([]byte{0})
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			want := before
			if padding {
				want += traceBytes
			}
			if got := state.Usage().AllocatedBytes; got != want {
				t.Fatalf("receiver=%t padding=%t reserved=%d want=%d", receiver, padding, got, want)
			}
			if !padding {
				continue
			}
			for _, limit := range []uint64{want - 1, want, want + 1} {
				bounded := append(append([]DecodeOption(nil), options...), WithLimits(Limits{MaxAllocatedBytes: limit}))
				next := NewBitBufferFromBytes([]byte{0})
				state := ApplyDecodeOptions(bounded...)
				err := next.SetDecodeOptionsAligned(state)
				if (limit < want) != errors.Is(err, ErrLimit) {
					t.Fatalf("receiver=%t limit=%d need=%d err=%v", receiver, limit, want, err)
				}
				if limit >= want && err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
