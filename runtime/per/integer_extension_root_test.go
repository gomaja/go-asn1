package per

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

// extensionForm writes the extension bit set to 1 and value as an
// unconstrained whole number, the form X.691 (02/2021) 13.1 gives a value
// outside the extension root (13.2.4 to 13.2.6).
func extensionForm(t *testing.T, value *big.Int, aligned bool) []byte {
	t.Helper()
	bb := NewBitBuffer()
	if err := bb.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	if err := encodeBigTwosComplement(bb, value, aligned); err != nil {
		t.Fatal(err)
	}
	return bb.CompleteBytes()
}

type integerExtensionCase struct {
	name   string
	decode func(bb *BitBuffer, aligned bool) (*big.Int, error)
	encode func(bb *BitBuffer, value *big.Int, aligned bool) error
	root   []int64 // values inside the extension root
	other  []int64 // values outside it
}

func pointer(value int64) *int64 { return &value }

var integerExtensionCases = []integerExtensionCase{
	{
		name: "constrained (0..7, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			decode := DecodeInteger
			if aligned {
				decode = DecodeIntegerAligned
			}
			value, err := decode(bb, pointer(0), pointer(7), true)
			return big.NewInt(value), err
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerAligned(bb, value.Int64(), pointer(0), pointer(7), true)
			}
			return EncodeInteger(bb, value.Int64(), pointer(0), pointer(7), true)
		},
		root:  []int64{0, 5, 7},
		other: []int64{-1, 8, 300},
	},
	{
		name: "semi-constrained (-5..MAX, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			decode := DecodeInteger
			if aligned {
				decode = DecodeIntegerAligned
			}
			value, err := decode(bb, pointer(-5), nil, true)
			return big.NewInt(value), err
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerAligned(bb, value.Int64(), pointer(-5), nil, true)
			}
			return EncodeInteger(bb, value.Int64(), pointer(-5), nil, true)
		},
		root:  []int64{-5, 3, 1 << 40},
		other: []int64{-6, -9},
	},
	{
		name: "upper bound only (MIN..10, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			decode := DecodeInteger
			if aligned {
				decode = DecodeIntegerAligned
			}
			value, err := decode(bb, nil, pointer(10), true)
			return big.NewInt(value), err
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerAligned(bb, value.Int64(), nil, pointer(10), true)
			}
			return EncodeInteger(bb, value.Int64(), nil, pointer(10), true)
		},
		root:  []int64{-1 << 40, 0, 10},
		other: []int64{11},
	},
	{
		name: "value set (1..3 | 5, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			decode := DecodeIntegerValueSet
			if aligned {
				decode = DecodeIntegerValueSetAligned
			}
			value, err := decode(bb, []IntegerRange{{1, 3}, {5, 5}}, true)
			return big.NewInt(value), err
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerValueSetAligned(bb, value.Int64(), []IntegerRange{{1, 3}, {5, 5}}, true)
			}
			return EncodeIntegerValueSet(bb, value.Int64(), []IntegerRange{{1, 3}, {5, 5}}, true)
		},
		root: []int64{1, 3, 5},
		// 4 lies between the root ranges, so it is outside the root.
		other: []int64{0, 4, 6},
	},
	{
		name: "big (0..7, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			if aligned {
				return DecodeIntegerBigAligned(bb, pointer(0), pointer(7), true)
			}
			return DecodeIntegerBig(bb, pointer(0), pointer(7), true)
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerBigAligned(bb, value, pointer(0), pointer(7), true)
			}
			return EncodeIntegerBig(bb, value, pointer(0), pointer(7), true)
		},
		root:  []int64{0, 5, 7},
		other: []int64{-1, 8},
	},
	{
		name: "big bounds (0..2^70, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			upper := new(big.Int).Lsh(big.NewInt(1), 70)
			if aligned {
				return DecodeIntegerBigBoundsAligned(bb, big.NewInt(0), upper, true)
			}
			return DecodeIntegerBigBounds(bb, big.NewInt(0), upper, true)
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			upper := new(big.Int).Lsh(big.NewInt(1), 70)
			if aligned {
				return EncodeIntegerBigBoundsAligned(bb, value, big.NewInt(0), upper, true)
			}
			return EncodeIntegerBigBounds(bb, value, big.NewInt(0), upper, true)
		},
		root:  []int64{0, 1 << 62},
		other: []int64{-1},
	},
	{
		name: "big value set (1..3 | 5, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			if aligned {
				return DecodeIntegerValueSetBigAligned(bb, []IntegerRange{{1, 3}, {5, 5}}, true)
			}
			return DecodeIntegerValueSetBig(bb, []IntegerRange{{1, 3}, {5, 5}}, true)
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerValueSetBigAligned(bb, value, []IntegerRange{{1, 3}, {5, 5}}, true)
			}
			return EncodeIntegerValueSetBig(bb, value, []IntegerRange{{1, 3}, {5, 5}}, true)
		},
		root:  []int64{1, 5},
		other: []int64{4, 9},
	},
	{
		name: "big uint64 root (2^63..2^64-1, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			if aligned {
				return DecodeIntegerBigUint64RootAligned(bb, 1<<63, 1<<64-1, true)
			}
			return DecodeIntegerBigUint64Root(bb, 1<<63, 1<<64-1, true)
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerBigUint64RootAligned(bb, value, 1<<63, 1<<64-1, true)
			}
			return EncodeIntegerBigUint64Root(bb, value, 1<<63, 1<<64-1, true)
		},
		root:  nil, // uint64 values above int64; see the case below
		other: []int64{0, -1, 1 << 62},
	},
	{
		name: "uint64 (5..2^64-1, ...)",
		decode: func(bb *BitBuffer, aligned bool) (*big.Int, error) {
			decode := DecodeIntegerUint64
			if aligned {
				decode = DecodeIntegerUint64Aligned
			}
			value, err := decode(bb, 5, 1<<64-1, true)
			return new(big.Int).SetUint64(value), err
		},
		encode: func(bb *BitBuffer, value *big.Int, aligned bool) error {
			if aligned {
				return EncodeIntegerUint64Aligned(bb, value.Uint64(), 5, 1<<64-1, true)
			}
			return EncodeIntegerUint64(bb, value.Uint64(), 5, 1<<64-1, true)
		},
		root:  []int64{5, 1 << 62},
		other: []int64{0, 4},
	},
}

// X.691 (02/2021) 13.1: the extension bit of an INTEGER is 1 only for a value
// outside the extension root. A root value sent in extension form is not a
// PER encoding of that value and cannot be re-encoded as received, so it is
// rejected, as for ENUMERATED, CHOICE, collection, string and size forms.
// A value outside the root decodes and re-encodes exactly.
func TestIntegerRejectsRootValueInExtensionForm(t *testing.T) {
	for _, tc := range integerExtensionCases {
		for _, aligned := range []bool{false, true} {
			variant := map[bool]string{false: "uper", true: "aper"}[aligned]
			for _, value := range tc.root {
				wire := extensionForm(t, big.NewInt(value), aligned)
				if _, err := tc.decode(NewBitBufferFromBytes(wire), aligned); !errors.Is(err, ErrInvalidValue) {
					t.Errorf("%s %s: root value %d in extension form %x: error %v, want ErrInvalidValue", variant, tc.name, value, wire, err)
				}
			}
			for _, value := range tc.other {
				if value < 0 && tc.name[:6] == "uint64" {
					continue
				}
				wire := extensionForm(t, big.NewInt(value), aligned)
				got, err := tc.decode(NewBitBufferFromBytes(wire), aligned)
				if err != nil || got.Cmp(big.NewInt(value)) != 0 {
					t.Errorf("%s %s: value %d in extension form %x decoded %v, %v", variant, tc.name, value, wire, got, err)
					continue
				}
				bb := NewBitBuffer()
				if err := tc.encode(bb, got, aligned); err != nil || !bytes.Equal(bb.CompleteBytes(), wire) {
					t.Errorf("%s %s: value %d re-encoded %x, %v, want %x", variant, tc.name, value, bb.CompleteBytes(), err, wire)
				}
			}
		}
	}
}

// A uint64 root value above int64 sent in extension form is rejected too.
func TestUint64IntegerRejectsRootValueInExtensionForm(t *testing.T) {
	value := new(big.Int).SetUint64(1<<64 - 2)
	for _, aligned := range []bool{false, true} {
		wire := extensionForm(t, value, aligned)
		var err error
		if aligned {
			_, err = DecodeIntegerUint64Aligned(NewBitBufferFromBytes(wire), 5, 1<<64-1, true)
		} else {
			_, err = DecodeIntegerUint64(NewBitBufferFromBytes(wire), 5, 1<<64-1, true)
		}
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("aligned %v uint64 %x: error %v, want ErrInvalidValue", aligned, wire, err)
		}
		if aligned {
			_, err = DecodeIntegerBigUint64RootAligned(NewBitBufferFromBytes(wire), 1<<63, 1<<64-1, true)
		} else {
			_, err = DecodeIntegerBigUint64Root(NewBitBufferFromBytes(wire), 1<<63, 1<<64-1, true)
		}
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("aligned %v big uint64 root %x: error %v, want ErrInvalidValue", aligned, wire, err)
		}
	}
}

// The example of go-asn1#105, I ::= INTEGER (0..7, ...) holding 5. pycrate
// 0.7.11 encodes 5 as 50 in both variants and decodes 808280 (UPER) and
// 800105 (APER) as 5: the extension bit, a one-octet length and 05 (13.2.4).
func TestIntegerRootValueInExtensionFormIssueExample(t *testing.T) {
	for _, tc := range []struct {
		aligned          bool
		valid, extension string
	}{
		{false, "50", "808280"},
		{true, "50", "800105"},
	} {
		decode := DecodeInteger
		if tc.aligned {
			decode = DecodeIntegerAligned
		}
		valid, _ := hex.DecodeString(tc.valid)
		if value, err := decode(NewBitBufferFromBytes(valid), pointer(0), pointer(7), true); err != nil || value != 5 {
			t.Errorf("aligned %v %s = %d, %v, want 5", tc.aligned, tc.valid, value, err)
		}
		extension, _ := hex.DecodeString(tc.extension)
		if !bytes.Equal(extension, extensionForm(t, big.NewInt(5), tc.aligned)) {
			t.Fatalf("aligned %v: extension form of 5 is not %s", tc.aligned, tc.extension)
		}
		if _, err := decode(NewBitBufferFromBytes(extension), pointer(0), pointer(7), true); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("aligned %v %s: error %v, want ErrInvalidValue", tc.aligned, tc.extension, err)
		}
	}
}

// FuzzExtensibleIntegerRoundTrip checks that every extensible INTEGER a
// decoder accepts re-encodes to exactly the bits it consumed, in both
// variants and for each kind of root. A root value in extension form, which
// re-encodes in root form, fails this property (X.691 (02/2021) 13.1).
func FuzzExtensibleIntegerRoundTrip(f *testing.F) {
	f.Add([]byte{0x80, 0x82, 0x80}, uint8(0))
	f.Add([]byte{0x80, 0x01, 0x05}, uint8(1))
	f.Add([]byte{0x50}, uint8(0))
	f.Add([]byte{0x80, 0x84, 0x80}, uint8(0))
	// 52 in root form for (MIN..10, ...), found by this target: a value
	// above the upper bound is outside the root.
	f.Add([]byte{0x00, 0x9a, 0x30}, uint8(0x94))
	f.Fuzz(func(t *testing.T, wire []byte, selector uint8) {
		tc := integerExtensionCases[int(selector>>1)%len(integerExtensionCases)]
		aligned := selector&1 == 1
		reader := NewBitBufferFromBytes(wire)
		value, err := tc.decode(reader, aligned)
		if err != nil {
			return
		}
		consumed := reader.BitPos()
		bb := NewBitBuffer()
		if err := tc.encode(bb, value, aligned); err != nil {
			t.Fatalf("%s aligned %v: re-encoding %v: %v", tc.name, aligned, value, err)
		}
		if bb.BitsWritten() != consumed || !prefixBitsEqual(bb.Bytes(), wire, consumed) {
			t.Fatalf("%s aligned %v: %v re-encoded %x (%d bits), decode consumed %d bits of %x", tc.name, aligned, value, bb.Bytes(), bb.BitsWritten(), consumed, wire)
		}
	})
}

// X.691 (02/2021) 13.2.4: an INTEGER with only an upper bound is an
// unconstrained whole number in its root. A value above the bound is outside
// the root (13.1) and outside the constraint: the int64 codecs reject it in
// root form, as the big-integer codecs do.
func TestIntegerUpperBoundOnlyRejectsValueAboveBound(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		for _, extensible := range []bool{false, true} {
			bb := NewBitBuffer()
			if extensible {
				if err := bb.WriteBit(0); err != nil {
					t.Fatal(err)
				}
			}
			if err := encodeBigTwosComplement(bb, big.NewInt(52), aligned); err != nil {
				t.Fatal(err)
			}
			decode, encode := DecodeInteger, EncodeInteger
			if aligned {
				decode, encode = DecodeIntegerAligned, EncodeIntegerAligned
			}
			if _, err := decode(NewBitBufferFromBytes(bb.CompleteBytes()), nil, pointer(10), extensible); !errors.Is(err, ErrConstraintViolation) {
				t.Errorf("aligned %v extensible %v: decoding 52 in root form: error %v, want ErrConstraintViolation", aligned, extensible, err)
			}
			if !extensible {
				if err := encode(NewBitBuffer(), 52, nil, pointer(10), false); !errors.Is(err, ErrConstraintViolation) {
					t.Errorf("aligned %v: encoding 52: error %v, want ErrConstraintViolation", aligned, err)
				}
			}
			if value, err := decode(NewBitBufferFromBytes(bb.CompleteBytes()), nil, nil, extensible); err != nil || value != 52 {
				t.Errorf("aligned %v extensible %v: unbounded decode = %d, %v", aligned, extensible, value, err)
			}
		}
	}
}
