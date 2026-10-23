// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/x2ap_specific_test.go; SHA-256 acef6a4c80e49a7f36fd3e6cd50c5045b0cd73d74e1de9a644c0b7159fda0da6.
package aper

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
)

// X.691 (02/2021) §§30.5.2, 30.5.7: X2AP URI-Address uses
// VisibleString with one aligned octet per character.
func TestX2APVisibleStringAligned(t *testing.T) {
	wire, err := hex.DecodeString("08687474703a2f2f78")
	if err != nil {
		t.Fatal(err)
	}
	bb := NewBitBufferFromBytes(wire)
	got, err := DecodeKnownMultiplierStringAligned(bb, 7, 0, 0, false)
	if err != nil || got != "http://x" {
		t.Fatalf("decode = %q, %v", got, err)
	}
	out := NewBitBuffer()
	if err := EncodeKnownMultiplierStringAligned(out, got, 7, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.CompleteBytes(), wire) {
		t.Fatalf("replay = %x", out.CompleteBytes())
	}
	if err := EncodeKnownMultiplierStringAligned(NewBitBuffer(), "\u0080", 7, 0, 0, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("outside VisibleString alphabet: %v", err)
	}
	if _, err := DecodeKnownMultiplierStringAligned(NewBitBufferFromBytes([]byte{1, 0x80}), 7, 0, 0, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("decoded character outside VisibleString alphabet: %v", err)
	}
	if err := EncodeKnownMultiplierStringAligned(NewBitBuffer(), "A", 0, 0, 0, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid width: %v", err)
	}
	fragmented := strings.Repeat("A", 16384)
	longWire := NewBitBuffer()
	if err := EncodeKnownMultiplierStringAligned(longWire, fragmented, 7, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if value, err := DecodeKnownMultiplierStringAligned(NewBitBufferFromBytes(longWire.CompleteBytes()), 7, 0, 0, false); err != nil || value != fragmented {
		t.Fatalf("fragmented string: length %d, error %v", len(value), err)
	}
	insideExtension := NewBitBuffer()
	if err := EncodeBoolean(insideExtension, true); err != nil {
		t.Fatal(err)
	}
	codec, err := identityCharacterCodec(7)
	if err != nil {
		t.Fatal(err)
	}
	if err := encodeLengthDelimitedCharacters(insideExtension, "A", 1, codec); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKnownMultiplierStringAlignedExt(NewBitBufferFromBytes(insideExtension.CompleteBytes()), 7, 1, 2, true, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("root length in extension form: %v", err)
	}
	if _, err := codec.payloadBits(math.MaxInt64); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("overflowing character payload length: %v", err)
	}
	if err := encodeLengthDelimitedCharacters(NewBitBuffer(), "A", 2, codec); !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "character count") {
		t.Fatalf("mismatched character count: %v", err)
	}
}

// X.691 (02/2021) §§11.5, 13: the unsigned root includes the upper
// boundary without overflowing signed arithmetic.
func TestX2APUint64Root(t *testing.T) {
	for _, value := range []uint64{0, 1, math.MaxInt64, math.MaxUint64} {
		out := NewBitBuffer()
		if err := EncodeIntegerUint64Aligned(out, value, 0, math.MaxUint64, false); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(out.CompleteBytes()), 0, math.MaxUint64, false)
		if err != nil || got != value {
			t.Fatalf("value %d: decoded %d, %v", value, got, err)
		}
	}
	if err := EncodeIntegerUint64Aligned(NewBitBuffer(), 2, 0, 1, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("out of root: %v", err)
	}
	buffer := NewBitBuffer()
	if err := buffer.WriteBits(5, 3); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), buffer.Bytes()...)
	if err := EncodeIntegerUint64Aligned(buffer, 7, 9, 3, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("inverted root: %v", err)
	}
	if !bytes.Equal(before, buffer.Bytes()) || buffer.BitsWritten() != 3 {
		t.Fatal("invalid root mutated the output")
	}
	malformed := NewBitBuffer()
	if err := EncodeConstrainedWholeNumber(malformed, 2, 1, 3); err != nil {
		t.Fatal(err)
	}
	if err := malformed.AlignToOctetWrite(); err != nil {
		t.Fatal(err)
	}
	if err := malformed.WriteBytes([]byte{0, 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(malformed.Bytes()), 0, 0xffffff, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nonminimal unsigned root: %v", err)
	}
	if _, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes([]byte{0xc0}), 0, 2, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("unsigned offset outside root: %v", err)
	}
	if err := uint64OffsetError(math.MaxUint64, math.MaxUint64-1, math.MaxUint64-1); err == nil || !strings.Contains(err.Error(), "36893488147419103229") {
		t.Fatalf("unsigned offset diagnostic overflowed: %v", err)
	}
	if _, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(nil), 9, 3, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("inverted decode root: %v", err)
	}
	insideExtension := NewBitBuffer()
	if err := EncodeBoolean(insideExtension, true); err != nil {
		t.Fatal(err)
	}
	if err := encodeUnconstrainedUint64(insideExtension, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(insideExtension.CompleteBytes()), 0, 2, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("root value in unsigned extension form: %v", err)
	}
	for _, malformedValue := range []struct {
		name    string
		content []byte
	}{
		{name: "negative", content: []byte{0x80}},
		{name: "redundant-zero", content: []byte{0, 3}},
		{name: "overlong", content: make([]byte, 10)},
	} {
		t.Run(malformedValue.name, func(t *testing.T) {
			wire := NewBitBuffer()
			if err := EncodeBoolean(wire, true); err != nil {
				t.Fatal(err)
			}
			if err := EncodeUnconstrainedLengthAligned(wire, int64(len(malformedValue.content))); err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteBytes(malformedValue.content); err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(wire.CompleteBytes()), 0, 2, true); !errors.Is(err, ErrInvalidValue) || malformedValue.name == "overlong" && !strings.Contains(err.Error(), "length") {
				t.Fatalf("malformed unsigned extension: %v", err)
			}
		})
	}
}

// X.691 (02/2021) §13: holes in the X2AP ExpectedActivityPeriod
// root remain invalid; the extension form carries values outside it.
func TestX2APDisjointActivityPeriod(t *testing.T) {
	ranges := []IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 180, Max: 181}}
	for _, value := range []int64{1, 30, 40, 50, 180, 181, 500} {
		out := NewBitBuffer()
		if err := EncodeIntegerValueSetBigAligned(out, big.NewInt(value), ranges, true); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeIntegerValueSetBigAligned(NewBitBufferFromBytes(out.CompleteBytes()), ranges, true)
		if err != nil || got.Int64() != value {
			t.Fatalf("value %d: decoded %v, %v", value, got, err)
		}
	}
	if err := EncodeIntegerValueSetBigAligned(NewBitBuffer(), big.NewInt(35), ranges, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("root gap: %v", err)
	}
	if err := EncodeIntegerValueSetBigAligned(NewBitBuffer(), big.NewInt(1), []IntegerRange{{Min: 2, Max: 1}}, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("inverted range: %v", err)
	}
	if err := EncodeIntegerValueSetBigAligned(NewBitBuffer(), big.NewInt(1), []IntegerRange{{Min: 1, Max: 3}, {Min: 3, Max: 5}}, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("overlapping ranges: %v", err)
	}
	if err := EncodeIntegerValueSetBigAligned(NewBitBuffer(), big.NewInt(1), nil, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty range set: %v", err)
	}
	if err := EncodeIntegerValueSetBigAligned(NewBitBuffer(), nil, ranges, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil integer: %v", err)
	}
	rootGap := NewBitBuffer()
	if err := EncodeConstrainedWholeNumberAligned(rootGap, 35, 1, 181); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerValueSetBigAligned(NewBitBufferFromBytes(rootGap.CompleteBytes()), ranges, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("decoded root gap: %v", err)
	}
	insideExtension := NewBitBuffer()
	if err := EncodeBoolean(insideExtension, true); err != nil {
		t.Fatal(err)
	}
	if err := encodeBigTwosComplement(insideExtension, big.NewInt(1), true); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerValueSetBigAligned(NewBitBufferFromBytes(insideExtension.CompleteBytes()), ranges, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("root value in disjoint-set extension form: %v", err)
	}
}

func TestX2APVisibleStringTruncationGrowsLinearly(t *testing.T) {
	for _, length := range []int{64, 128, 256, 512} {
		// The determinant claims one more character than the supplied payload.
		out := NewBitBuffer()
		if err := EncodeUnconstrainedLengthAligned(out, int64(length+1)); err != nil {
			t.Fatal(err)
		}
		if err := out.WriteBytes([]byte(strings.Repeat("A", length))); err != nil {
			t.Fatal(err)
		}
		input := out.CompleteBytes()
		bb := NewBitBufferFromBytes(input)
		if _, err := DecodeKnownMultiplierStringAligned(bb, 7, 0, 0, false); !errors.Is(err, ErrTruncated) || !strings.Contains(err.Error(), "requires") {
			t.Fatalf("length %d: %v", length, err)
		}
		if bb.bitPos > len(input)*8 {
			t.Fatalf("length %d: read past input", length)
		}
		allocations := testing.AllocsPerRun(20, func() {
			reader := NewBitBufferFromBytes(input)
			_, _ = DecodeKnownMultiplierStringAligned(reader, 7, 0, 0, false)
		})
		if allocations > 8 {
			t.Fatalf("length %d: truncated decode allocated %.0f times", length, allocations)
		}
	}
}
