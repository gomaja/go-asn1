package per

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var (
	digitsAlphabet = PermittedAlphabet{'0', '9'}
	upperAlphabet  = PermittedAlphabet{'A', 'Z'}
	hostAlphabet   = PermittedAlphabet{'-', '.', '0', '9', 'A', 'Z', 'a', 'z'}
	dialAlphabet   = PermittedAlphabet{'#', '#', '*', '*', ',', ',', '0', '9'}
	oneAlphabet    = PermittedAlphabet{'A', 'A'}
)

// characterStringVector is one string field, optionally between BOOLEAN
// TRUE fields, so that alignment shows in the octets. The expected octets
// were derived field by field from ITU-T X.691 (02/2021); pycrate 0.7.11's
// decoder accepts all of them except where noted (see TestCharacterStringVectors).
type characterStringVector struct {
	name        string
	aligned     bool
	lead, trail bool
	alphabet    PermittedAlphabet // nil: identity over alphabetBits
	bits        int
	lb, ub      int64
	constrained bool
	extensible  bool
	value       string
	hex         string
}

var characterStringVectors = []characterStringVector{
	// go-asn1#101: S1AP ENBname, PrintableString (SIZE (1..150, ...)).
	{name: "ENBname ab", aligned: true, bits: 7, lb: 1, ub: 150, constrained: true, extensible: true, value: "ab", hex: "00806162"},
	{name: "ENBname eNB-1", aligned: true, bits: 7, lb: 1, ub: 150, constrained: true, extensible: true, value: "eNB-1", hex: "0200654e422d31"},
	{name: "ENBname extension", aligned: true, bits: 7, lb: 1, ub: 150, constrained: true, extensible: true, value: strings.Repeat("a", 151), hex: "808097" + strings.Repeat("61", 151)},
	{name: "ENBname uper", bits: 7, lb: 1, ub: 150, constrained: true, extensible: true, value: "ab", hex: "00e1c4"},
	{name: "VisibleString", aligned: true, bits: 7, value: "http://x", hex: "08687474703a2f2f78"},
	{name: "VisibleString uper", bits: 7, value: "http://x", hex: "08d1d3a7074bd7f8"},
	{name: "IA5String", aligned: true, bits: 7, value: "a\x7f", hex: "02617f"},
	// 30.5.6: a fixed size aligns when aub*b > 16.
	{name: "fixed 16 bits", aligned: true, lead: true, bits: 7, lb: 2, ub: 2, constrained: true, value: "ab", hex: "b0b100"},
	{name: "fixed 24 bits", aligned: true, lead: true, bits: 7, lb: 3, ub: 3, constrained: true, value: "abc", hex: "80616263"},
	// 30.5.7: a variable size aligns when aub*b >= 16 (pycrate always aligns).
	{name: "variable 8 bits", aligned: true, lead: true, bits: 7, lb: 0, ub: 1, constrained: true, value: "a", hex: "d840"},
	{name: "variable 16 bits", aligned: true, lead: true, bits: 7, lb: 1, ub: 2, constrained: true, value: "a", hex: "8061"},
	// 11.9.3.3: nothing, not even padding, follows a zero length (pycrate pads).
	{name: "zero length", aligned: true, trail: true, bits: 7, lb: 0, ub: 4, constrained: true, value: "", hex: "10"},
	{name: "zero length uper", trail: true, bits: 7, lb: 0, ub: 4, constrained: true, value: "", hex: "10"},
	// NumericString: 30.5.4 b) indexes in 4 bits in both variants.
	{name: "NumericString", aligned: true, alphabet: NumericStringAlphabet, value: "123", hex: "032340"},
	{name: "NumericString uper", alphabet: NumericStringAlphabet, value: "1 9", hex: "0320a0"},
	{name: "NumericString fixed 12 bits", aligned: true, lead: true, alphabet: NumericStringAlphabet, lb: 3, ub: 3, constrained: true, value: "123", hex: "91a0"},
	{name: "NumericString fixed 16 bits", aligned: true, lead: true, alphabet: NumericStringAlphabet, lb: 4, ub: 4, constrained: true, value: "1234", hex: "91a280"},
	{name: "NumericString fixed 20 bits", aligned: true, lead: true, alphabet: NumericStringAlphabet, lb: 5, ub: 5, constrained: true, value: "12345", hex: "80234560"},
	{name: "NumericString variable 12 bits", aligned: true, lead: true, alphabet: NumericStringAlphabet, lb: 1, ub: 3, constrained: true, value: "12", hex: "a460"},
	{name: "NumericString variable 16 bits", aligned: true, lead: true, alphabet: NumericStringAlphabet, lb: 1, ub: 4, constrained: true, value: "12", hex: "a023"},
	{name: "NumericString variable uper", lead: true, alphabet: NumericStringAlphabet, lb: 1, ub: 4, constrained: true, value: "12", hex: "a460"},
	// BMPString and UniversalString: B = B2.
	{name: "BMPString fixed 16 bits", aligned: true, lead: true, bits: 16, lb: 1, ub: 1, constrained: true, value: "é", hex: "807480"},
	{name: "BMPString fixed 32 bits", aligned: true, lead: true, bits: 16, lb: 2, ub: 2, constrained: true, value: "é中", hex: "8000e94e2d"},
	{name: "BMPString", aligned: true, bits: 16, value: "中", hex: "014e2d"},
	{name: "UniversalString", aligned: true, bits: 32, value: "\U0001f600", hex: "010001f600"},
	// PER-visible permitted alphabets.
	{name: "FROM digits", aligned: true, alphabet: digitsAlphabet, value: "19", hex: "0219"},
	{name: "FROM digits uper", alphabet: digitsAlphabet, value: "19", hex: "0219"},
	{name: "FROM upper", aligned: true, alphabet: upperAlphabet, value: "AZ", hex: "02415a"},
	{name: "FROM upper uper", alphabet: upperAlphabet, value: "AZ", hex: "020640"},
	{name: "FROM host", aligned: true, alphabet: hostAlphabet, value: "a.Z-9", hex: "05612e5a2d39"},
	{name: "FROM host uper", alphabet: hostAlphabet, value: "a.Z-9", hex: "059819402c"},
	{name: "FROM dial", aligned: true, alphabet: dialAlphabet, value: "*1#,", hex: "041402"},
	{name: "FROM dial uper", alphabet: dialAlphabet, value: "*1#,", hex: "041402"},
	{name: "FROM upper root", aligned: true, lead: true, alphabet: upperAlphabet, lb: 1, ub: 2, constrained: true, extensible: true, value: "AZ", hex: "a0415a"},
	{name: "FROM upper extension", aligned: true, lead: true, alphabet: upperAlphabet, lb: 1, ub: 2, constrained: true, extensible: true, value: "ABC", hex: "c003414243"},
	{name: "FROM upper extension uper", lead: true, alphabet: upperAlphabet, lb: 1, ub: 2, constrained: true, extensible: true, value: "ABC", hex: "c0c01100"},
	// A one-character alphabet: N = 1, so B = 0 and B2 = 1 (30.5.2). pycrate
	// 0.7.11's encoder produces the same UPER octets; its decoder fails on B = 0.
	{name: "one character fixed uper", lead: true, alphabet: oneAlphabet, lb: 2, ub: 2, constrained: true, value: "AA", hex: "80"},
	{name: "one character fixed", aligned: true, lead: true, alphabet: oneAlphabet, lb: 2, ub: 2, constrained: true, value: "AA", hex: "80"},
	{name: "one character variable uper", lead: true, alphabet: oneAlphabet, lb: 0, ub: 3, constrained: true, value: "AA", hex: "c0"},
	{name: "one character variable", aligned: true, lead: true, alphabet: oneAlphabet, lb: 0, ub: 3, constrained: true, value: "AA", hex: "c0"},
	{name: "one character unconstrained uper", alphabet: oneAlphabet, value: "AAA", hex: "03"},
	{name: "one character unconstrained", aligned: true, alphabet: oneAlphabet, value: "AAA", hex: "0300"},
	{name: "one character empty uper", alphabet: oneAlphabet, value: "", hex: "00"},
	{name: "one character fragmented uper", alphabet: oneAlphabet, value: strings.Repeat("A", 70000), hex: "c49170"},
	{name: "one character extension uper", alphabet: oneAlphabet, lb: 1, ub: 2, constrained: true, extensible: true, value: "AAA", hex: "8180"},
}

func (vector characterStringVector) encode(bb *BitBuffer, value string) error {
	if vector.lead {
		if err := EncodeBoolean(bb, true); err != nil {
			return err
		}
	}
	var err error
	switch {
	case vector.alphabet != nil && vector.aligned:
		err = EncodeAlphabetStringAligned(bb, value, vector.alphabet, vector.lb, vector.ub, vector.constrained, vector.extensible)
	case vector.alphabet != nil:
		err = EncodeAlphabetString(bb, value, vector.alphabet, vector.lb, vector.ub, vector.constrained, vector.extensible)
	case vector.aligned:
		err = EncodeKnownMultiplierStringAlignedExt(bb, value, vector.bits, vector.lb, vector.ub, vector.constrained, vector.extensible)
	default:
		err = EncodeKnownMultiplierStringExt(bb, value, vector.bits, vector.lb, vector.ub, vector.constrained, vector.extensible)
	}
	if err != nil || !vector.trail {
		return err
	}
	return EncodeBoolean(bb, true)
}

func (vector characterStringVector) decode(bb *BitBuffer) (string, error) {
	if vector.lead {
		if lead, err := DecodeBoolean(bb); err != nil || !lead {
			return "", errors.Join(err, errors.New("leading BOOLEAN"))
		}
	}
	var value string
	var err error
	switch {
	case vector.alphabet != nil && vector.aligned:
		value, err = DecodeAlphabetStringAligned(bb, vector.alphabet, vector.lb, vector.ub, vector.constrained, vector.extensible)
	case vector.alphabet != nil:
		value, err = DecodeAlphabetString(bb, vector.alphabet, vector.lb, vector.ub, vector.constrained, vector.extensible)
	case vector.aligned:
		value, err = DecodeKnownMultiplierStringAlignedExt(bb, vector.bits, vector.lb, vector.ub, vector.constrained, vector.extensible)
	default:
		value, err = DecodeKnownMultiplierStringExt(bb, vector.bits, vector.lb, vector.ub, vector.constrained, vector.extensible)
	}
	if err != nil || !vector.trail {
		return value, err
	}
	if trail, err := DecodeBoolean(bb); err != nil || !trail {
		return "", errors.Join(err, errors.New("trailing BOOLEAN"))
	}
	return value, nil
}

func TestCharacterStringVectors(t *testing.T) {
	for _, vector := range characterStringVectors {
		t.Run(vector.name, func(t *testing.T) {
			want, err := hex.DecodeString(vector.hex)
			if err != nil {
				t.Fatal(err)
			}
			bb := NewBitBuffer()
			if err := vector.encode(bb, vector.value); err != nil {
				t.Fatalf("encode %q: %v", vector.value, err)
			}
			if got := bb.CompleteBytes(); !bytes.Equal(got, want) {
				t.Fatalf("encode %q = %x, want %x", vector.value, got, want)
			}
			reader := NewBitBufferFromBytes(want)
			got, err := vector.decode(reader)
			if err != nil || got != vector.value {
				t.Fatalf("decode %x = %q, %v; want %q", want, got, err, vector.value)
			}
			if err := ValidateFinalPadding(reader); err != nil {
				t.Fatalf("decode %x left %d bits: %v", want, reader.BitsRemaining(), err)
			}
		})
	}
}

// go-asn1#101: the 7-bit encoding the aligned codec used to produce is not
// a conforming encoding of "ab" and must not decode as it.
func TestAlignedKnownMultiplierStringRejectsUnalignedWidth(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0x00, 0x80, 0xc3, 0x88})
	if got, err := DecodeKnownMultiplierStringAlignedExt(bb, 7, 1, 150, true, true); err == nil && got == "ab" {
		t.Fatalf("decoded the 7-bit encoding as %q", got)
	}
}

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

func TestAlphabetStringRejectsCharactersOutsideTheAlphabet(t *testing.T) {
	for _, aligned := range []bool{false, true} {
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
			var err error
			if aligned {
				err = EncodeAlphabetStringAligned(bb, tc.value, tc.alphabet, 0, 0, false, false)
			} else {
				err = EncodeAlphabetString(bb, tc.value, tc.alphabet, 0, 0, false, false)
			}
			if err == nil {
				t.Errorf("aligned %v: encoded %q outside %v", aligned, tc.value, tc.alphabet)
			}
			if bb.BitsWritten() != 0 {
				t.Errorf("aligned %v: %q wrote %d bits before failing", aligned, tc.value, bb.BitsWritten())
			}
		}
	}
	// Index 11 is past the eleven NumericString characters; 'a' and '/' are
	// outside the identity-mapped aligned alphabets.
	for _, tc := range []struct {
		aligned  bool
		alphabet PermittedAlphabet
		wire     string
	}{
		{false, NumericStringAlphabet, "01b0"},
		{true, NumericStringAlphabet, "01b0"},
		{true, upperAlphabet, "0161"},
		// '/' lies in the gap between the '-'..'.' and '0'..'9' ranges.
		{true, hostAlphabet, "012f"},
		{false, digitsAlphabet, "01a0"},
	} {
		wire, _ := hex.DecodeString(tc.wire)
		var err error
		if tc.aligned {
			_, err = DecodeAlphabetStringAligned(NewBitBufferFromBytes(wire), tc.alphabet, 0, 0, false, false)
		} else {
			_, err = DecodeAlphabetString(NewBitBufferFromBytes(wire), tc.alphabet, 0, 0, false, false)
		}
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("decode %s aligned %v: error %v, want ErrInvalidValue", tc.wire, tc.aligned, err)
		}
	}
}

// X.691 (02/2021) 30.4 marks only a length outside the root as an extension;
// a root length in extension form is rejected, as for collections.
func TestCharacterStringRejectsRootLengthInExtensionForm(t *testing.T) {
	for _, tc := range []struct {
		aligned bool
		wire    string
	}{
		{false, "8080"},    // extension bit, length 1, one 1-bit character
		{true, "800161"},   // extension bit, padding, length 1, 'a'
		{true, "80026162"}, // length 2, the root upper bound
	} {
		wire, _ := hex.DecodeString(tc.wire)
		var err error
		if tc.aligned {
			_, err = DecodeKnownMultiplierStringAlignedExt(NewBitBufferFromBytes(wire), 7, 1, 2, true, true)
		} else {
			_, err = DecodeAlphabetString(NewBitBufferFromBytes(wire), PermittedAlphabet{0xe9, 0xe9, 0x4e2d, 0x4e2d}, 1, 2, true, true)
		}
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("aligned %v %s: error %v, want ErrInvalidValue", tc.aligned, tc.wire, err)
		}
	}
}

// Zero-bit characters consume no input, so DecodeOptions bounds the length
// that a length determinant may give them; schema lengths below 64K are not
// affected.
func TestZeroWidthCharactersAreBounded(t *testing.T) {
	decode := func(wire []byte, options DecodeOptions, lb, ub int64, constrained bool) (string, error) {
		bb := NewBitBufferFromBytes(wire)
		bb.SetDecodeOptions(options)
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
	parent.SetDecodeOptions(DecodeOptions{MaxZeroWidthCharacters: 69999})
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
	bb.SetDecodeOptions(DecodeOptions{MaxZeroWidthCharacters: 1})
	if _, err := DecodeAlphabetString(bb, upperAlphabet, 0, 0, false, false); !errors.Is(err, ErrTruncated) {
		t.Fatalf("5-bit characters: %v, want ErrTruncated", err)
	}
}

// The aligned identity codec still bounds values by B: an IA5String octet
// above 0x7f is not an IA5String character.
func TestAlignedKnownMultiplierStringBoundsValuesByAlphabetBits(t *testing.T) {
	if err := EncodeKnownMultiplierStringAligned(NewBitBuffer(), "\x80", 7, 0, 0, false); !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("encode 0x80: %v, want ErrConstraintViolation", err)
	}
	if _, err := DecodeKnownMultiplierStringAligned(NewBitBufferFromBytes([]byte{0x01, 0x80}), 7, 0, 0, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("decode 0x80: %v, want ErrInvalidValue", err)
	}
}

// Fragmented alphabet strings use the same character mapping in every
// fragment (X.691 (02/2021) 11.9.3.8).
func TestFragmentedAlphabetStringRoundTrip(t *testing.T) {
	value := strings.Repeat("0123456789 ", 6000)
	for _, aligned := range []bool{false, true} {
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeAlphabetStringAligned(bb, value, NumericStringAlphabet, 0, 0, false, false)
		} else {
			err = EncodeAlphabetString(bb, value, NumericStringAlphabet, 0, 0, false, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		reader := NewBitBufferFromBytes(bb.CompleteBytes())
		var got string
		if aligned {
			got, err = DecodeAlphabetStringAligned(reader, NumericStringAlphabet, 0, 0, false, false)
		} else {
			got, err = DecodeAlphabetString(reader, NumericStringAlphabet, 0, 0, false, false)
		}
		if err != nil || got != value {
			t.Fatalf("aligned %v: round trip %d characters, %v", aligned, len(got), err)
		}
	}
}

func TestAlphabetStringDoesNotAllocateTheAlphabet(t *testing.T) {
	bb := NewBitBuffer()
	allocations := testing.AllocsPerRun(100, func() {
		bb = NewBitBuffer()
		_ = EncodeAlphabetStringAligned(bb, "abc", PermittedAlphabet{'a', 'z'}, 1, 8, true, false)
	})
	if allocations > 2 {
		t.Fatalf("encode allocates %v times per call", allocations)
	}
}

// FuzzAlphabetStringDecodeRoundTrip checks that any accepted wire re-encodes
// to exactly the bits it consumed.
func FuzzAlphabetStringDecodeRoundTrip(f *testing.F) {
	for _, vector := range characterStringVectors {
		wire, _ := hex.DecodeString(vector.hex)
		f.Add(wire, vector.aligned, uint8(0))
	}
	// A root length in extension form, found by this target.
	f.Add([]byte{0x80, 0x80}, false, uint8(0x8f))
	f.Fuzz(func(t *testing.T, wire []byte, aligned bool, selector uint8) {
		alphabets := []PermittedAlphabet{nil, NumericStringAlphabet, upperAlphabet, hostAlphabet, dialAlphabet, {0xe9, 0xe9, 0x4e2d, 0x4e2d}, oneAlphabet}
		alphabet := alphabets[int(selector)%len(alphabets)]
		sizes := [][3]int64{{0, 0, 0}, {1, 4, 1}, {0, 1, 1}, {3, 3, 1}, {5, 5, 1}, {1, 150, 1}}
		size := sizes[int(selector/8)%len(sizes)]
		extensible := selector&0x80 != 0
		vector := characterStringVector{aligned: aligned, alphabet: alphabet, bits: 7, lb: size[0], ub: size[1], constrained: size[2] == 1, extensible: extensible}
		reader := NewBitBufferFromBytes(wire)
		value, err := vector.decode(reader)
		if err != nil {
			return
		}
		consumed := reader.BitPos()
		bb := NewBitBuffer()
		if err := vector.encode(bb, value); err != nil {
			t.Fatalf("re-encode %q: %v", value, err)
		}
		if bb.BitsWritten() != consumed {
			t.Fatalf("re-encode %q wrote %d bits, decode consumed %d", value, bb.BitsWritten(), consumed)
		}
		if !prefixBitsEqual(bb.Bytes(), wire, consumed) {
			t.Fatalf("re-encode %q = %x differs from the %d consumed bits of %x", value, bb.Bytes(), consumed, wire)
		}
	})
}

func prefixBitsEqual(a, b []byte, bitCount int) bool {
	for index := 0; index < bitCount; index++ {
		mask := byte(0x80) >> (index % 8)
		if a[index/8]&mask != b[index/8]&mask {
			return false
		}
	}
	return true
}
