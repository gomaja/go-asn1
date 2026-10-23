// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/padding_preserve_test.go; SHA-256 7b73aaa43469f33ae4ca3c65f2d6aad4e030375b41a358fff62219a95cc2ebf3.
package aper

import (
	"bytes"
	"errors"
	"testing"
)

func TestCompletePaddingPreservesObservedBits(t *testing.T) {
	for _, read := range []struct {
		name string
		fn   func(*BitBuffer) (CompletePadding, error)
	}{
		{"top-level", CaptureFinalPadding},
		{"open-type", CaptureOpenTypePadding},
	} {
		t.Run(read.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{0xaf})
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
			if err != nil || !bytes.Equal(wire, []byte{0xaf}) {
				t.Fatalf("re-encoded = %x, %v; want af", wire, err)
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
