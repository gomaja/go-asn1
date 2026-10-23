// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_set_ported_test.go; SHA-256 ef75ef0f669735b6c150fcb433ad3ffaae44a82e686a0f926d07e377edf70b97.
package aper

import (
	"errors"
	"testing"
)

func TestIntegerValueSetAPERRejectsDecodedGap(t *testing.T) {
	t.Parallel()

	ranges := []IntegerRange{{Min: 1, Max: 3}, {Min: 5, Max: 5}}
	bb := NewBitBuffer()
	if err := EncodeConstrainedWholeNumberAligned(bb, 4, 1, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerValueSetAligned(NewBitBufferFromBytes(bb.Bytes()), ranges, false); err == nil {
		t.Fatal("DecodeIntegerValueSetAligned accepted a root gap")
	}

	bb = NewBitBuffer()
	if err := EncodeIntegerValueSetAligned(bb, 4, ranges, true); err != nil {
		t.Fatalf("EncodeIntegerValueSetAligned(extension): %v", err)
	}
	got, err := DecodeIntegerValueSetAligned(NewBitBufferFromBytes(bb.Bytes()), ranges, true)
	if err != nil || got != 4 {
		t.Fatalf("DecodeIntegerValueSetAligned(extension) = %d, %v", got, err)
	}
}

func TestDecodeIntegerUint64AlignedRejectsNonMinimalConstrainedValue(t *testing.T) {
	t.Parallel()

	bb := NewBitBuffer()
	if err := EncodeConstrainedWholeNumber(bb, 2, 1, 3); err != nil {
		t.Fatal(err)
	}
	if err := bb.AlignToOctetWrite(); err != nil {
		t.Fatal(err)
	}
	if err := bb.WriteBytes([]byte{0x00, 0x01}); err != nil {
		t.Fatal(err)
	}

	_, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(bb.Bytes()), 0, 0xffffff, false)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("decode error = %v, want ErrInvalidValue", err)
	}
}
