// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/charstring_test.go; SHA-256 620b397601ebe4c81b50cf26a424f6a2db6db1db20dc4ee72d9f5750f55d8e83.
package uper

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

var oneAlphabet = PermittedAlphabet{'A', 'A'}
var upperAlphabet = PermittedAlphabet{'A', 'Z'}

// Ported UPER vectors from go-asn1 f2c57b4 runtime/per/charstring_test.go.
// X.691 (02/2021) §§30.5.2–30.5.4 determine both indexes and their widths.
func TestLPPAlphabetStringVectors(t *testing.T) {
	for _, tc := range []struct {
		alphabet    PermittedAlphabet
		value, wire string
	}{
		{NumericStringAlphabet, "1 9", "0320a0"},
		{PermittedAlphabet{'0', '9'}, "19", "0219"},
		{upperAlphabet, "AZ", "020640"},
		{PermittedAlphabet{'-', '.', '0', '9', 'A', 'Z', 'a', 'z'}, "a.Z-9", "059819402c"},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			want, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			bb := NewBitBuffer()
			if err := EncodeAlphabetString(bb, tc.value, tc.alphabet, 0, 0, false, false); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.CompleteBytes(), want) {
				t.Fatalf("wire = %x, want %x", bb.CompleteBytes(), want)
			}
			reader := NewBitBufferFromBytes(want)
			value, err := DecodeAlphabetString(reader, tc.alphabet, 0, 0, false, false)
			if err != nil || value != tc.value {
				t.Fatalf("value = %q, %v; want %q", value, err, tc.value)
			}
			if err := ValidateFinalPadding(reader); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLPPAlphabetStringRefusals(t *testing.T) {
	for _, alphabet := range []PermittedAlphabet{nil, {'a'}, {'b', 'a'}, {'a', 'c', 'c', 'd'}, {'a', 'c', 'd', 'e'}} {
		if err := EncodeAlphabetString(NewBitBuffer(), "a", alphabet, 0, 0, false, false); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("alphabet %v: %v", alphabet, err)
		}
		if _, err := DecodeAlphabetString(NewBitBuffer(), alphabet, 0, 0, false, false); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("alphabet %v: %v", alphabet, err)
		}
	}
	bb := NewBitBuffer()
	if err := EncodeAlphabetString(bb, "12a", NumericStringAlphabet, 0, 0, false, false); !errors.Is(err, ErrConstraintViolation) || bb.BitsWritten() != 0 {
		t.Fatalf("invalid character wrote bits: %v", err)
	}
	if _, err := DecodeAlphabetString(NewBitBufferFromBytes([]byte{1, 0xb0}), NumericStringAlphabet, 0, 0, false, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("unused character index: %v", err)
	}
}

func TestZeroWidthCharactersAreBounded(t *testing.T) {
	decode := func(wire []byte, options DecodeOptions, lb, ub int64, constrained bool) (string, error) {
		bb := NewBitBufferFromBytes(wire)
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		return DecodeAlphabetString(bb, oneAlphabet, lb, ub, constrained, false)
	}
	// 70000 characters from three octets: within the default limit.
	if got, err := decode([]byte{0xc4, 0x91, 0x70}, DecodeOptions{}, 0, 0, false); err != nil || len(got) != 70000 {
		t.Fatalf("70000 characters: %d, %v", len(got), err)
	}
	if _, err := decode([]byte{0xc4, 0x91, 0x70}, DecodeOptions{MaxZeroWidthCharacters: 69999}, 0, 0, false); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("70000 characters with a limit of 69999: %v, want ErrResourceLimit", err)
	}
	if got, err := decode([]byte{0xc4, 0x91, 0x70}, DecodeOptions{MaxZeroWidthCharacters: 70000}, 0, 0, false); err != nil || len(got) != 70000 {
		t.Fatalf("70000 characters with a limit of 70000: %d, %v", len(got), err)
	}
	// Seventeen full 64K fragments claim 1,114,112 characters in 18 octets.
	flood := append(bytes.Repeat([]byte{0xc4}, 17), 0x00)
	if _, err := decode(flood, DecodeOptions{}, 0, 0, false); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("seventeen 64K fragments: %v, want ErrResourceLimit", err)
	}
	// A nested decode, such as an open type, inherits the limit.
	parent := NewBitBuffer()
	if err := parent.SetDecodeOptions(DecodeOptions{MaxZeroWidthCharacters: 69999}); err != nil {
		t.Fatal(err)
	}
	child := NewBitBufferFromBytes([]byte{0xc4, 0x91, 0x70})
	child.InheritDecodeOptions(parent)
	if _, err := DecodeAlphabetString(child, oneAlphabet, 0, 0, false, false); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("inherited limit: %v, want ErrResourceLimit", err)
	}
	// A constrained length below 64K is bounded by the schema alone.
	if got, err := decode([]byte{0xff, 0xff}, DecodeOptions{MaxZeroWidthCharacters: 1}, 0, 65535, true); err != nil || len(got) != 65535 {
		t.Fatalf("65535 constrained characters: %d, %v", len(got), err)
	}
	// Characters with at least one bit are bounded by the input.
	bb := NewBitBufferFromBytes([]byte{0xc4, 0x91, 0x70})
	if err := bb.SetDecodeOptions(DecodeOptions{MaxZeroWidthCharacters: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAlphabetString(bb, upperAlphabet, 0, 0, false, false); !errors.Is(err, ErrTruncated) {
		t.Fatalf("5-bit characters: %v, want ErrTruncated", err)
	}
}

// The aligned identity codec still bounds values by B: an IA5String octet
// above 0x7f is not an IA5String character.
