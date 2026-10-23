// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/charstring_ported_test.go; SHA-256 755114216d4eeff0f0e4705d830de9c85f8ee791f23f35590e3e626b90698e4a.
package aper

import (
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
)

var (
	upperAlphabet = PermittedAlphabet{'A', 'Z'}
	hostAlphabet  = PermittedAlphabet{'-', '.', '0', '9', 'A', 'Z', 'a', 'z'}
)

func TestAlignedCharacterBits(t *testing.T) {
	for alphabetBits, want := range map[int]int{0: 1, 1: 1, 2: 2, 3: 4, 4: 4, 5: 8, 7: 8, 8: 8, 9: 16, 16: 16, 17: 32, 32: 32} {
		if got := alignedCharacterBits(alphabetBits); got != want {
			t.Errorf("B2 for B=%d = %d, want %d", alphabetBits, got, want)
		}
	}
}

func TestPermittedAlphabetCharacterCodec(t *testing.T) {
	for _, tc := range []struct {
		name          string
		alphabet      PermittedAlphabet
		aligned       bool
		bits          int
		indexed, wide bool
	}{
		{"NumericString uper", NumericStringAlphabet, false, 4, true, false},
		{"NumericString aper", NumericStringAlphabet, true, 4, true, false},
		{"upper uper", upperAlphabet, false, 5, true, false},
		{"upper aper", upperAlphabet, true, 8, false, false},
		{"host uper", hostAlphabet, false, 6, true, false},
		{"host aper", hostAlphabet, true, 8, false, false},
		// 30.5.4 a): the largest value 3 fits in B = 2 bits.
		{"low values", PermittedAlphabet{1, 3}, false, 2, false, false},
		{"two characters", PermittedAlphabet{'a', 'b'}, true, 1, true, false},
		{"one character aligned", PermittedAlphabet{'a', 'a'}, true, 1, true, false},
		// 30.5.2: N = 1 gives B = 0, so UNALIGNED characters take no bits.
		{"one character unaligned", PermittedAlphabet{'a', 'a'}, false, 0, true, false},
		{"BMP subset", PermittedAlphabet{0xe9, 0xe9, 0x4e2d, 0x4e2d}, true, 1, true, true},
		{"whole BMP", PermittedAlphabet{0, 0xffff}, true, 16, false, true},
		{"whole UniversalString", PermittedAlphabet{0, 0xffffffff}, false, 32, false, true},
	} {
		codec, err := tc.alphabet.characterCodec(tc.aligned)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if codec.bits != tc.bits || codec.indexed != tc.indexed || codec.wide != tc.wide {
			t.Errorf("%s: bits %d indexed %v wide %v; want %d %v %v", tc.name, codec.bits, codec.indexed, codec.wide, tc.bits, tc.indexed, tc.wide)
		}
	}
}

func TestPermittedAlphabetRejectsMalformedAlphabets(t *testing.T) {
	for _, alphabet := range []PermittedAlphabet{
		nil,
		{'a'},
		{'b', 'a'},
		{'a', 'c', 'c', 'd'},
		{'a', 'c', 'd', 'e'},
		{'c', 'd', 'a', 'b'},
	} {
		for _, aligned := range []bool{false, true} {
			if _, err := alphabet.characterCodec(aligned); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("alphabet %v aligned %v: error %v, want ErrInvalidValue", alphabet, aligned, err)
			}
		}
	}
}

func TestAlignedKnownMultiplierStringBoundsValuesByAlphabetBits(t *testing.T) {
	if err := EncodeKnownMultiplierStringAligned(NewBitBuffer(), "\x80", 7, 0, 0, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("encode 0x80: %v, want ErrConstraintViolation", err)
	}
	if _, err := DecodeKnownMultiplierStringAligned(NewBitBufferFromBytes([]byte{0x01, 0x80}), 7, 0, 0, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("decode 0x80: %v, want ErrInvalidValue", err)
	}
}

func TestAlignedAlphabetStringRejectsValuesOutsideAlphabet(t *testing.T) {
	for _, tc := range []struct {
		alphabet PermittedAlphabet
		value    string
	}{
		{NumericStringAlphabet, "12a"},
		{upperAlphabet, "Ab"},
		{hostAlphabet, "a_b"},
		{PermittedAlphabet{0xe9, 0xe9, 0x4e2d, 0x4e2d}, "éx"},
		{PermittedAlphabet{0xe9, 0xe9, 0x4e2d, 0x4e2d}, "\xff"},
	} {
		bb := NewBitBuffer()
		if err := EncodeAlphabetStringAligned(bb, tc.value, tc.alphabet, 0, 0, false, false); !errors.Is(err, ErrConstraintViolation) && !errors.Is(err, ErrInvalidValue) {
			t.Errorf("encoded %q outside %v: %v", tc.value, tc.alphabet, err)
		}
		if bb.BitsWritten() != 0 {
			t.Errorf("%q wrote %d bits before failing", tc.value, bb.BitsWritten())
		}
	}
	for _, tc := range []struct {
		alphabet PermittedAlphabet
		wire     string
	}{
		{NumericStringAlphabet, "01b0"},
		{upperAlphabet, "0161"},
		{hostAlphabet, "012f"},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeAlphabetStringAligned(NewBitBufferFromBytes(wire), tc.alphabet, 0, 0, false, false); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("decode %s: %v, want ErrInvalidValue", tc.wire, err)
		}
	}
}

func TestAlignedCharacterStringRejectsRootLengthInExtension(t *testing.T) {
	// X.691 (02/2021) §30.4: an extension length must lie outside the root.
	for _, wire := range []string{"800161", "80026162"} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeKnownMultiplierStringAlignedExt(NewBitBufferFromBytes(data), 7, 1, 2, true, true); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("extension form %s: %v, want ErrInvalidValue", wire, err)
		}
	}
}

func TestAlignedFragmentedAlphabetStringRoundTrip(t *testing.T) {
	// X.691 (02/2021) §11.9.3.8: each fragment uses the same alphabet.
	value := strings.Repeat("0123456789 ", 6000)
	bb := NewBitBuffer()
	if err := EncodeAlphabetStringAligned(bb, value, NumericStringAlphabet, 0, 0, false, false); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAlphabetStringAligned(NewBitBufferFromBytes(bb.CompleteBytes()), NumericStringAlphabet, 0, 0, false, false)
	if err != nil || got != value {
		t.Fatalf("fragmented string: %d characters, %v", len(got), err)
	}
}

func TestAlignedCharacterCodecRejectsInvalidInternalInputs(t *testing.T) {
	for _, width := range []int{-1, 0, 33} {
		if err := validateKnownMultiplierWidth(width); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("known multiplier width %d: %v", width, err)
		}
		if width != 0 {
			if _, err := (characterCodec{bits: width}).payloadBits(1); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("payload width %d: %v", width, err)
			}
		}
	}
	codec := characterCodec{bits: 32, valueBits: 32, wide: true}
	if _, err := codec.length("\xff"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("invalid UTF-8: %v", err)
	}
	if _, err := codec.payloadBits(-1); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("negative length: %v", err)
	}
	if _, err := codec.payloadBits(math.MaxInt64); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("overflowing payload: %v", err)
	}
	if _, err := codec.read(NewBitBuffer(), 1); !errors.Is(err, ErrTruncated) || err.Error() != "per: data truncated: character string requires 32 bits with 0 remaining" {
		t.Errorf("truncated payload: %v", err)
	}
	if _, err := codec.read(NewBitBufferFromBytes([]byte{0x80, 0, 0, 0}), 1); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("invalid Unicode scalar: %v", err)
	}
	narrow := characterCodec{bits: 16, valueBits: 16}
	if _, err := narrow.read(NewBitBufferFromBytes([]byte{0x01, 0x00}), 1); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("oversized narrow character: %v", err)
	}
	if err := encodeLengthDelimitedCharacters(NewBitBuffer(), "abc", 2, characterCodec{bits: 8, valueBits: 8}, true); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("mismatched character count: %v", err)
	}
}
