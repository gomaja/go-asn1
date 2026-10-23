// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/charstring_ported_test.go; SHA-256 19e163bb6b8c5d1e5ce2549872267413f8f54f33a1fbd7cab6a0ecb27ef9875e.
package aper

import (
	"errors"
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
