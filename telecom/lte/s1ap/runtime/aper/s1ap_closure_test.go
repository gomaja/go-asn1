// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/s1ap_closure_test.go; SHA-256 b7b033c17bb766b6aa9653fbc6bdf9e2f8ca27ceba6a58b5a737c82ec164c5d9.
package aper

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"testing"
)

func TestS1APKnownMultiplierAligned(t *testing.T) {
	// TS 36.413 V19.2.0 §9.3.1: ENBname is PrintableString SIZE(1..150,...).
	// X.691 (02/2021) §30.5.2 uses B2=8 for this aligned value.
	want := []byte{0x00, 0x80, 'a', 'b'}
	bb := NewBitBuffer()
	if err := EncodeKnownMultiplierStringAlignedExt(bb, "ab", 7, 1, 150, true, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bb.CompleteBytes(), want) {
		t.Fatalf("encoded %x", bb.CompleteBytes())
	}
	value, err := DecodeKnownMultiplierStringAlignedExt(NewBitBufferFromBytes(want), 7, 1, 150, true, true)
	if err != nil || value != "ab" {
		t.Fatalf("decoded %q, %v", value, err)
	}
	if err := EncodeKnownMultiplierStringAlignedExt(NewBitBuffer(), "\x80", 7, 1, 150, true, true); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("invalid alphabet: %v", err)
	}
}

func TestS1APUint64Aligned(t *testing.T) {
	// X.691 (02/2021) §§11.5, 13.1–13.2: full-width root values.
	for _, value := range []uint64{0, 1, 1<<63 + 17, math.MaxUint64} {
		bb := NewBitBuffer()
		if err := EncodeIntegerUint64Aligned(bb, value, 0, math.MaxUint64, false); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(bb.CompleteBytes()), 0, math.MaxUint64, false)
		if err != nil || got != value {
			t.Fatalf("%d => %d, %v", value, got, err)
		}
	}
	bb := NewBitBuffer()
	if err := EncodeIntegerUint64Aligned(bb, 7, 9, 3, true); !errors.Is(err, ErrInvalidValue) || bb.BitsWritten() != 0 {
		t.Fatalf("reversed range: %v, %d bits", err, bb.BitsWritten())
	}
	bad := NewBitBuffer()
	if err := EncodeBoolean(bad, true); err != nil {
		t.Fatal(err)
	}
	if err := encodeUnconstrainedUint64(bad, 5, true); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(bad.CompleteBytes()), 0, 10, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("root value carried in extension: %v", err)
	}
}

func TestS1APBigValueSetAligned(t *testing.T) {
	// X.691 (02/2021) §13.2: an unused root code is refused.
	ranges := []IntegerRange{{Min: 1, Max: 3}, {Min: 5, Max: 5}}
	bb := NewBitBuffer()
	if err := EncodeIntegerValueSetBigAligned(bb, big.NewInt(5), ranges, false); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeIntegerValueSetBigAligned(NewBitBufferFromBytes(bb.CompleteBytes()), ranges, false)
	if err != nil || got.Int64() != 5 {
		t.Fatalf("value set: %v, %v", got, err)
	}
	bad := NewBitBuffer()
	if err := EncodeConstrainedWholeNumberAligned(bad, 4, 1, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerValueSetBigAligned(NewBitBufferFromBytes(bad.CompleteBytes()), ranges, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("gap accepted: %v", err)
	}
	if err := EncodeIntegerValueSetBigAligned(NewBitBuffer(), big.NewInt(2), []IntegerRange{{Min: 1, Max: 3}, {Min: 3, Max: 5}}, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("overlapping ranges: %v", err)
	}
}

func TestS1APNestedZeroWidthLimit(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0})
	if err := parent.SetDecodeOptionsAligned(DecodeOptions{MaxZeroWidthCharacters: 17}); err != nil {
		t.Fatal(err)
	}
	child := NewNestedDecodeBuffer([]byte{0}, parent)
	if got := child.zeroWidthCharacterLimit(); got != 17 {
		t.Fatalf("nested zero-width limit = %d, want 17", got)
	}
}
