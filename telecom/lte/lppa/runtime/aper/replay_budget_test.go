// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_budget_test.go; SHA-256 9082ce79f2caac9b285b6c5789174c5a5e5db91d4181182b00856329389cb72d.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"unsafe"
)

func TestOwnedReaderOverflowReservesBeforeAllocation(t *testing.T) {
	input := []byte{0, 0, 1, 0x80, 0}
	setup := func(limit uint64) (DecodeState, *BitBuffer, OpaqueOpenType) {
		owned, state := OwnDecodeInputOptions(input, WithLimits(Limits{MaxAllocatedBytes: limit}))
		parent := NewCompleteDecodeBuffer(owned, state)
		if err := parent.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		if _, err := parent.ReadBits(16); err != nil {
			t.Fatal(err)
		}
		raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
		if err != nil {
			t.Fatal(err)
		}
		return state, parent, raw
	}
	state, parent, _ := setup(0)
	inline := len(parent.Budget().owner.buffers)
	readerBytes := uint64(unsafe.Sizeof(BitBuffer{}))
	required := state.Usage().AllocatedBytes + 2*readerBytes
	for _, limit := range []uint64{required - 1, required, required + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			state, parent, raw := setup(limit)
			// The root consumed one inline reader. Keep all children live to prove
			// that overflowing the array cannot reuse a previous reader's cursor.
			children := make([]*BitBuffer, 0, inline+1)
			for range inline + 1 {
				children = append(children, raw.ChildDecodeBuffer())
			}
			_, err := children[len(children)-1].ReadBit()
			_, err = FinishDecode(state, err)
			if (limit < required) != errors.Is(err, ErrLimit) {
				t.Fatalf("limit=%d required=%d error=%v", limit, required, err)
			}
			if limit < required {
				var located *DecodeError
				if !errors.As(err, &located) || located.Kind != Limit || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: 32, End: 32}) {
					t.Fatalf("unlocated reader refusal: %v", err)
				}
				position := parent.BitPos()
				before := state.Usage().AllocatedBytes
				if n := testing.AllocsPerRun(20, func() { _ = raw.ChildDecodeBuffer() }); n != 0 {
					t.Fatalf("failed reader allocated %.0f times", n)
				}
				if parent.BitPos() != position {
					t.Fatal("failed reader changed its parent cursor")
				}
				if state.Usage().AllocatedBytes != before {
					t.Fatal("failed reader consumed another reservation")
				}
				if _, err := parent.ReadBit(); !errors.Is(err, ErrLimit) {
					t.Fatalf("parent lost shared exhaustion: %v", err)
				}
				return
			}
			if got := state.Usage().AllocatedBytes; got != required {
				t.Fatalf("reader storage charged %d bytes, want %d", got, required)
			}
			for i, child := range children {
				if i == len(children)-1 {
					continue
				}
				got, err := child.ReadBits(8)
				if err != nil || got != 0x80 {
					t.Fatalf("child %d cursor changed: %x %v", i, got, err)
				}
			}
			if !bytes.Equal(parent.Budget().owner.original, input) {
				t.Fatal("child changed received bytes")
			}
		})
	}
}
