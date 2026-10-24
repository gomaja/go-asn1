// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/padding_preserve_test.go; SHA-256 46caee322191b8bd8b236d34f90097577fa88fe04027ca17693c5ab47bb0b5bc.
package aper

import (
	"bytes"
	"errors"
	"testing"
)

func TestCompletePaddingPreservesZeroBits(t *testing.T) {
	for _, read := range []struct {
		name string
		fn   func(*BitBuffer) (CompletePadding, error)
	}{
		{"top-level", CaptureFinalPadding},
		{"open-type", CaptureOpenTypePadding},
	} {
		t.Run(read.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{0xa0})
			if value, err := bb.ReadBits(4); err != nil || value != 0xa {
				t.Fatalf("decoded value = %x, %v", value, err)
			}
			pad, err := read.fn(bb)
			if err != nil {
				t.Fatal(err)
			}
			out := NewBitBuffer()
			if err := out.WriteBits(0xa, 4); err != nil {
				t.Fatal(err)
			}
			wire, err := out.CompleteBytesWithPadding(pad)
			if err != nil || !bytes.Equal(wire, []byte{0xa0}) {
				t.Fatalf("re-encoded = %x, %v; want a0", wire, err)
			}
			canonical, err := out.CompleteBytesWithPadding(CompletePadding{})
			if err != nil || !bytes.Equal(canonical, []byte{0xa0}) {
				t.Fatalf("new value = %x, %v; want a0", canonical, err)
			}
			if err := out.WriteBit(1); err != nil {
				t.Fatal(err)
			}
			// An edited value whose padding width changed is padded as a new one.
			if edited, err := out.CompleteBytesWithPadding(pad); err != nil || !bytes.Equal(edited, []byte{0xa8}) {
				t.Fatalf("changed length = %x, %v; want a8", edited, err)
			}
		})
	}
}

func TestCompletePaddingRejectsAppendedOctet(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0xaf, 0x00})
	_, _ = bb.ReadBits(4)
	if _, err := CaptureFinalPadding(bb); !errors.Is(err, ErrExtraData) {
		t.Fatalf("appended octet error = %v, want extra data", err)
	}
}
