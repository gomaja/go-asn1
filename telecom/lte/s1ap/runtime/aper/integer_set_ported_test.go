// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_set_ported_test.go; SHA-256 6953e6959960aee27f8c5f861b27613485432efc228f8fee7ba92f39e592393d.
package aper

import (
	"encoding/hex"
	"errors"
	"math/big"
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

func TestAlignedIntegerValueSetRejectsInvalidInputs(t *testing.T) {
	bb := NewBitBuffer()
	for _, ranges := range [][]IntegerRange{
		nil,
		{{Min: 2, Max: 1}},
		{{Min: 1, Max: 3}, {Min: 3, Max: 4}},
	} {
		if err := EncodeIntegerValueSetAligned(bb, 2, ranges, false); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ranges %v: %v, want ErrInvalidValue", ranges, err)
		}
	}
	if err := EncodeIntegerValueSetAligned(bb, 4, []IntegerRange{{Min: 1, Max: 3}}, false); !errors.Is(err, ErrConstraintViolation) || err.Error() != "per: constraint violation: 4 is outside the permitted INTEGER value set" {
		t.Errorf("outside value set: %v", err)
	}
	if err := encodeIntegerValueSetBig(bb, nil, []IntegerRange{{Min: 1, Max: 3}}, false, true); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("nil big value: %v", err)
	}
	if err := encodeIntegerValueSetBig(bb, big.NewInt(4), []IntegerRange{{Min: 1, Max: 3}}, false, true); !errors.Is(err, ErrConstraintViolation) || err.Error() != "per: constraint violation: 4 is outside the permitted INTEGER value set" {
		t.Errorf("big value outside set: %v", err)
	}
	if err := encodeIntegerBigUint64Root(bb, nil, 0, 3, false, true); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("nil uint64 root value: %v", err)
	}
	if err := encodeIntegerBigUint64Root(bb, big.NewInt(2), 3, 1, false, true); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("reversed uint64 root range: %v", err)
	}
	if err := encodeIntegerBigUint64Root(bb, big.NewInt(4), 0, 3, false, true); !errors.Is(err, ErrConstraintViolation) || err.Error() != "per: constraint violation: 4 is outside uint64 INTEGER root [0..3]" {
		t.Errorf("big value outside uint64 root: %v", err)
	}
	if _, err := decodeIntegerBigUint64Root(NewBitBuffer(), 3, 1, false, true); !errors.Is(err, ErrInvalidValue) || err.Error() != "per: value out of range: invalid uint64 INTEGER range [3..1]" {
		t.Errorf("decode reversed uint64 root range: %v", err)
	}
	if _, err := DecodeIntegerUint64Aligned(NewBitBuffer(), 3, 1, false); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("decode reversed uint64 range: %v", err)
	}
	valid := NewBitBuffer()
	if err := encodeIntegerBigUint64Root(valid, big.NewInt(2), 0, 3, false, true); err != nil {
		t.Fatalf("encode valid big uint64 root: %v", err)
	}
	if got, err := decodeIntegerBigUint64Root(NewBitBufferFromBytes(valid.CompleteBytes()), 0, 3, false, true); err != nil || got.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("decode valid big uint64 root: %v, %v", got, err)
	}
}

func TestAlignedUint64RejectsInvalidExtensionOctets(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"zero length", nil},
		{"too long", make([]byte, 10)},
		{"negative", []byte{0x80}},
		{"redundant leading zero", []byte{0x00, 0x7f}},
		{"nine octets without sign pad", []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}},
	} {
		bb := NewBitBuffer()
		if err := EncodeUnconstrainedLengthAligned(bb, int64(len(tc.data))); err != nil {
			t.Fatalf("%s length: %v", tc.name, err)
		}
		if err := bb.WriteBytes(tc.data); err != nil {
			t.Fatalf("%s data: %v", tc.name, err)
		}
		if _, err := decodeUnconstrainedUint64(NewBitBufferFromBytes(bb.CompleteBytes()), true); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: %v, want ErrInvalidValue", tc.name, err)
		}
	}
}

func TestAlignedUint64RejectsOffsetOutsideRoot(t *testing.T) {
	// X.691 (02/2021) §11.5: the two-bit offset 3 exceeds the root 0..2.
	_, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes([]byte{0xc0}), 0, 2, false)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("offset outside root: %v, want ErrInvalidValue", err)
	}
}

func TestAlignedUint64ExtensionRoundTrip(t *testing.T) {
	bb := NewBitBuffer()
	if err := EncodeIntegerUint64Aligned(bb, 42, 0, 10, true); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(bb.CompleteBytes()), 0, 10, true)
	if err != nil || got != 42 {
		t.Fatalf("decoded extension = %d, %v", got, err)
	}
}

func TestIntegerBigPointerConversionHandlesNil(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("nil integer pointer caused panic: %v", recovered)
		}
	}()
	if got := bigIntFromInt64Pointer(nil); got != nil {
		t.Errorf("nil pointer converted to %v", got)
	}
	value := int64(-3)
	if got := bigIntFromInt64Pointer(&value); got == nil || got.Cmp(big.NewInt(-3)) != 0 {
		t.Errorf("value pointer converted to %v", got)
	}
}

func TestAlignedIntegerSetRejectsRootValueInExtension(t *testing.T) {
	// X.691 (02/2021) §13.1: extension form carries values outside the root.
	ranges := []IntegerRange{{Min: 1, Max: 3}}
	for _, tc := range []struct {
		name   string
		encode func(*BitBuffer) error
		decode func(*BitBuffer) error
	}{
		{"int64 value set", func(bb *BitBuffer) error {
			return EncodeUnconstrainedWholeNumberAligned(bb, 2)
		}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerValueSetAligned(bb, ranges, true)
			return err
		}},
		{"big value set", func(bb *BitBuffer) error {
			return encodeBigTwosComplement(bb, big.NewInt(2), true)
		}, func(bb *BitBuffer) error {
			_, err := decodeIntegerValueSetBig(bb, ranges, true, true)
			return err
		}},
		{"big uint64 root", func(bb *BitBuffer) error {
			return encodeBigTwosComplement(bb, big.NewInt(2), true)
		}, func(bb *BitBuffer) error {
			_, err := decodeIntegerBigUint64Root(bb, 0, 3, true, true)
			return err
		}},
	} {
		bb := NewBitBuffer()
		if err := EncodeBoolean(bb, true); err != nil {
			t.Fatal(err)
		}
		if err := tc.encode(bb); err != nil {
			t.Fatalf("%s encoding: %v", tc.name, err)
		}
		if err := tc.decode(NewBitBufferFromBytes(bb.CompleteBytes())); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s decoded root value in extension: %v, want ErrInvalidValue", tc.name, err)
		}
	}
}

func TestAlignedUint64RangeWidthBoundaries(t *testing.T) {
	// X.691 (02/2021) §11.5: 255 chooses one octet, then 256..65535 use two.
	for _, tc := range []struct {
		upper uint64
		wire  string
	}{
		{254, "fe"},
		{255, "ff"},
		{256, "0100"},
		{65535, "ffff"},
		{65536, ""},
	} {
		bb := NewBitBuffer()
		if err := EncodeIntegerUint64Aligned(bb, tc.upper, 0, tc.upper, false); err != nil {
			t.Fatalf("upper %d encoding: %v", tc.upper, err)
		}
		wire := bb.CompleteBytes()
		if tc.wire != "" && hex.EncodeToString(wire) != tc.wire {
			t.Errorf("upper %d wire %x, want %s", tc.upper, wire, tc.wire)
		}
		got, err := DecodeIntegerUint64Aligned(NewBitBufferFromBytes(wire), 0, tc.upper, false)
		if err != nil || got != tc.upper {
			t.Errorf("upper %d decoded %d, %v", tc.upper, got, err)
		}
	}
}
