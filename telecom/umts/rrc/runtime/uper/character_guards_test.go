// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/character_guards_test.go; SHA-256 ae649c7e86ce9d7ca2780264d0f999b49f4b59d023cd75268c8ee43083aeb546.
package uper

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// X.691 (02/2021) §30.5: whole-alphabet characters use their scalar value,
// lengths count characters, and the extension bit means a length outside the root.
func TestWholeAlphabetCharactersAndBounds(t *testing.T) {
	for _, tc := range []struct {
		bits  int
		value string
	}{{7, "ab"}, {8, "\x80a"}, {16, "a€"}, {32, "a😀"}} {
		for _, size := range []struct {
			lb, ub                  int64
			constrained, extensible bool
		}{{0, 0, false, false}, {0, 4, true, false}, {2, 2, true, false}, {1, 1, true, true}, {0, 65536, true, false}} {
			writer := NewBitBuffer()
			if err := EncodeKnownMultiplierStringExt(writer, tc.value, tc.bits, size.lb, size.ub, size.constrained, size.extensible); err != nil {
				t.Fatal(err)
			}
			reader := NewBitBufferFromBytes(writer.CompleteBytes())
			value, err := DecodeKnownMultiplierStringExt(reader, tc.bits, size.lb, size.ub, size.constrained, size.extensible)
			if err != nil || value != tc.value {
				t.Fatalf("%d %q %v", tc.bits, value, err)
			}
		}
	}
	for _, tc := range []struct {
		bits  int
		value string
	}{{0, "a"}, {33, "a"}, {7, "\x80"}, {16, "\xff"}, {9, "€"}} {
		if err := EncodeKnownMultiplierString(NewBitBuffer(), tc.value, tc.bits, 0, 0, false); err == nil {
			t.Fatal("invalid character/width accepted", tc)
		}
	}
	for _, bits := range []int{0, 33} {
		if _, err := DecodeKnownMultiplierString(NewBitBuffer(), bits, 0, 0, false); err == nil {
			t.Fatal("invalid decode width accepted")
		}
	}
	for _, bound := range [][2]int64{{-1, 1}, {3, 2}} {
		if err := EncodeKnownMultiplierString(NewBitBuffer(), "a", 7, bound[0], bound[1], true); err == nil {
			t.Fatal("invalid bounds accepted")
		}
		if _, err := DecodeKnownMultiplierString(NewBitBuffer(), 7, bound[0], bound[1], true); err == nil {
			t.Fatal("invalid decode bounds accepted")
		}
	}
	if err := EncodeKnownMultiplierString(NewBitBuffer(), "ab", 7, 1, 1, true); err == nil {
		t.Fatal("root length violation accepted")
	}
	if _, err := DecodeKnownMultiplierStringExt(NewBitBuffer(), 7, 0, 2, true, true); err == nil {
		t.Fatal("missing extension bit accepted")
	}
	for _, code := range []uint64{0xd800, 0x110000, 0x80000000} {
		writer := NewBitBuffer()
		if err := writer.WriteBits(code, 32); err != nil {
			t.Fatal(err)
		}
		codec := characterCodec{bits: 32, valueBits: 32, wide: true}
		if _, err := codec.read(NewBitBufferFromBytes(writer.Bytes()), 1); !errors.Is(err, ErrInvalidValue) {
			t.Fatal("invalid scalar accepted", err)
		}
	}
	// A complete extension carrying a root length is refused (§30.4).
	writer := NewBitBuffer()
	if err := writer.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	if err := EncodeKnownMultiplierString(writer, "a", 7, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKnownMultiplierStringExt(NewBitBufferFromBytes(writer.Bytes()), 7, 0, 2, true, true); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("root length in extension accepted", err)
	}
}

func TestCharacterInternalSafetyGuards(t *testing.T) {
	for _, width := range []int{-1, 33} {
		if _, err := (characterCodec{bits: width}).payloadBits(1); err == nil {
			t.Fatal("invalid payload width")
		}
	}
	if bits, err := (characterCodec{}).payloadBits(math.MaxInt64); err != nil || bits != 0 {
		t.Fatal(bits, err)
	}
	for _, length := range []int64{-1, math.MaxInt64} {
		if _, err := (characterCodec{bits: 32}).payloadBits(length); err == nil {
			t.Fatal("invalid payload length")
		}
	}
	for _, codec := range []characterCodec{{bits: 7, valueBits: 7}, {bits: 9, valueBits: 8, wide: true}, {bits: 65, valueBits: 7, wide: true}} {
		if err := codec.write(NewBitBuffer(), "€"); err == nil {
			t.Fatal("invalid internal write accepted")
		}
	}
	for _, codec := range []characterCodec{{bits: 16, valueBits: 16}, {bits: 16, valueBits: 7, wide: true}, {bits: 65, valueBits: 7, wide: true}} {
		writer := NewBitBuffer()
		if err := writer.WriteBits(0x1234, 16); err != nil {
			t.Fatal(err)
		}
		if _, err := codec.read(NewBitBufferFromBytes(writer.Bytes()), 1); err == nil {
			t.Fatal("invalid internal read accepted")
		}
	}
	if err := encodeLengthDelimitedCharacters(NewBitBuffer(), "invalid", 99, characterCodec{bits: 7, valueBits: 7}, false); err == nil {
		t.Fatal("invalid internal count accepted")
	}
	var log ToleranceLog
	reader := NewBitBuffer()
	if err := reader.SetDecodeOptions(DecodeOptions{MaxZeroWidthCharacters: 12, TrailingBitsTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	if reader.zeroWidthCharacterLimit() != 12 || NewBitBuffer().zeroWidthCharacterLimit() != DefaultMaxZeroWidthCharacters {
		t.Fatal("character count limit changed")
	}
	codec := characterCodec{bits: 0, valueBits: 1}
	if _, _, err := decodeLengthDelimitedCharacters(NewBitBufferFromBytes([]byte{0xc4, 0}), codec, false, math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	reader = NewBitBufferFromBytes([]byte{13})
	if err := reader.SetDecodeOptions(DecodeOptions{MaxZeroWidthCharacters: 12}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeLengthDelimitedCharacters(reader, codec, false, math.MaxInt64); !errors.Is(err, ErrResourceLimit) {
		t.Fatal("zero width limit ignored", err)
	}
}

func TestFragmentedWholeAlphabetCharacters(t *testing.T) {
	for _, tc := range []struct {
		bits int
		unit string
	}{{7, "a"}, {16, "€"}} {
		value := strings.Repeat(tc.unit, 16385)
		writer := NewBitBuffer()
		if err := EncodeKnownMultiplierString(writer, value, tc.bits, 0, 0, false); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeKnownMultiplierString(NewBitBufferFromBytes(writer.Bytes()), tc.bits, 0, 0, false)
		if err != nil || got != value {
			t.Fatal("fragmented characters changed", err)
		}
	}
}
