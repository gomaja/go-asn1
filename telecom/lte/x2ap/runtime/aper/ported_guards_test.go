// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/ported_guards_test.go; SHA-256 347f7b9062a0bb275f30845d76d02da865759875cba840c7d3d97b10b6328961.
package aper

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
)

func TestPortedBufferGuards(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*BitBuffer) error
	}{
		{"read bit", func(bb *BitBuffer) error { _, e := bb.ReadBit(); return e }},
		{"read bits", func(bb *BitBuffer) error { _, e := bb.ReadBits(1); return e }},
		{"read bytes", func(bb *BitBuffer) error { _, e := bb.ReadBytes(1); return e }},
		{"read packed", func(bb *BitBuffer) error { _, e := bb.ReadBitsToBytes(1); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bb := range []*BitBuffer{{invalidLength: true}, {bitPos: -1}} {
				if e := tc.run(bb); !errors.Is(e, ErrInvalidValue) {
					t.Fatalf("invalid buffer: %v", e)
				}
			}
			if e := tc.run(NewBitBufferFromBytes(nil)); !errors.Is(e, ErrTruncated) {
				t.Fatalf("empty buffer: %v", e)
			}
		})
	}
	for _, width := range []int{-1, 65} {
		if _, e := NewBitBufferFromBytes(nil).ReadBits(width); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
		if e := NewBitBuffer().WriteBits(0, width); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
	}
	if e := (&BitBuffer{bitPos: -1}).WriteBit(0); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := NewBitBufferFromBytes(nil).ReadBytes(-1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := NewBitBufferFromBytes(nil).ReadBitsToBytes(-1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := NewBitBuffer().WriteBitsFromBytes(nil, 1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := NewBitBuffer().WriteBitsFromBytes(nil, -1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := octetsForBitLength(-1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if n, e := octetsForBitLength(math.MaxInt); e != nil || n != math.MaxInt/8+1 {
		t.Fatalf("rounding: %d %v", n, e)
	}
}

func TestPortedNumberGuards(t *testing.T) {
	if e := EncodeConstrainedWholeNumberAligned(NewBitBuffer(), 0, 1, 0); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := DecodeConstrainedWholeNumberAligned(NewBitBufferFromBytes(nil), 1, 0); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := EncodeConstrainedWholeNumberAligned(NewBitBuffer(), 3, 0, 2); !errors.Is(e, ErrConstraintViolation) {
		t.Fatal(e)
	}
	if _, e := DecodeConstrainedWholeNumberAligned(NewBitBufferFromBytes([]byte{0xc0}), 0, 2); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := DecodeConstrainedWholeNumberAligned(NewBitBufferFromBytes([]byte{0xff, 0xff}), 0, 256); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	for _, v := range []int64{math.MaxInt64, 0, -1} {
		if _, e := addNonNegativeOffset(v, math.MaxUint64); !errors.Is(e, ErrInvalidValue) {
			t.Fatalf("offset %d: %v", v, e)
		}
	}
	if _, e := addExtensionIndex(1, math.MaxInt64); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := EncodeNormallySmallNonNegativeAligned(NewBitBuffer(), -1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := EncodeNormallySmallLengthAligned(NewBitBuffer(), 0); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, _, e := decodeExtensionBitmapBits(NewBitBufferFromBytes(nil), -1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, _, e := decodeExtensionBitmapBits(NewBitBufferFromBytes([]byte{0}), 8); !errors.Is(e, ErrTruncated) {
		t.Fatal(e)
	}
	for _, count := range []int{-1, 0} {
		if e := EncodeEnumeratedAligned(NewBitBuffer(), 0, count, true); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
		if _, e := DecodeEnumeratedAligned(NewBitBufferFromBytes(nil), count, true); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
	}
	if e := EncodeEnumeratedAligned(NewBitBuffer(), 1, 1, false); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := EncodeSemiConstrainedWholeNumberAligned(NewBitBuffer(), 0, 1); !errors.Is(e, ErrConstraintViolation) {
		t.Fatal(e)
	}
	lb, ub := int64(0), int64(2)
	writer := NewBitBuffer()
	if e := writer.WriteBit(1); e != nil {
		t.Fatal(e)
	}
	if e := EncodeUnconstrainedWholeNumberAligned(writer, 1); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeIntegerAligned(NewBitBufferFromBytes(writer.Bytes()), &lb, &ub, true); !errors.Is(e, ErrInvalidValue) {
		t.Fatalf("root in extension: %v", e)
	}
	if _, e := DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(writer.Bytes()), big.NewInt(0), big.NewInt(2), true); !errors.Is(e, ErrInvalidValue) {
		t.Fatalf("big root in extension: %v", e)
	}
}

func TestPortedConstraintGuards(t *testing.T) {
	for _, size := range []SizeConstraint{{Lower: -1, HasLower: true}, {Upper: -1, HasUpper: true}, {Lower: 2, Upper: 1, HasLower: true, HasUpper: true}} {
		if _, e := DecodeCollection(NewBitBufferFromBytes(nil), size, true, func(int64, int64) error { return nil }); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
	}
	for _, size := range []SizeConstraint{{Lower: 2, HasLower: true}, {Upper: 0, HasUpper: true}} {
		if e := EncodeCollection(NewBitBuffer(), 1, size, true, func(int64, int64) error { return nil }); !errors.Is(e, ErrConstraintViolation) {
			t.Fatal(e)
		}
	}
	if e := EncodeCollection(NewBitBuffer(), 0, SizeConstraint{}, true, nil); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := DecodeCollection(NewBitBufferFromBytes(nil), SizeConstraint{}, true, nil); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := EncodeLengthFragments(NewBitBuffer(), -1, true, func(int64, int64) error { return nil }); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := decodeLengthFragmentsBounded(NewBitBufferFromBytes(nil), true, -1, func(int64, int64) error { return nil }); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if e := EncodeLengthFragments(NewBitBuffer(), 0, true, nil); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := DecodeLengthFragments(NewBitBufferFromBytes(nil), true, nil); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	for _, octets := range []bool{false, true} {
		bb := NewBitBuffer()
		var err error
		if octets {
			err = EncodeOctetStringAligned(bb, []byte{1}, -1, 2, true)
		} else {
			err = EncodeBitStringAligned(bb, []byte{0}, 1, -1, 2, true)
		}
		if !errors.Is(err, ErrInvalidValue) || bb.BitsWritten() != 0 {
			t.Fatalf("size preflight: %v", err)
		}
	}
	bb := NewBitBuffer()
	if e := bb.WriteBit(1); e != nil {
		t.Fatal(e)
	}
	if e := bb.WriteBitsFromBytes(nil, 1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if !bytes.Equal(bb.Bytes(), []byte{0x80}) || bb.BitsWritten() != 1 {
		t.Fatal("failed encode mutated buffer")
	}
}

func TestPortedPaddingGuards(t *testing.T) {
	for _, padding := range []CompletePadding{{bits: 1, count: 8}, {bits: 2, count: 1}} {
		if _, e := NewBitBuffer().CompleteBytesWithPadding(padding); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
	}
	bb := NewBitBufferFromBytes([]byte{0x81})
	if _, e := bb.ReadBit(); e != nil {
		t.Fatal(e)
	}
	if e := bb.AlignToOctetRead(); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	for _, position := range []int{-1, 2} {
		bb := NewBitBufferFromBytes([]byte{0})
		bb.bitPos = 1
		a := ExtensionAdditions{start: position}
		if _, e := a.RecoveryEncoder(bb); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
		if _, e := a.RecordRecovery(bb, NewBitBuffer(), FinalPadding{}); !errors.Is(e, ErrInvalidValue) {
			t.Fatal(e)
		}
	}
}

func TestPortedOIDErrorParity(t *testing.T) {
	for _, tc := range []struct {
		wire           []byte
		want           string
		classification error
	}{
		{[]byte{0}, "object identifier: ber: value out of range: invalid object identifier: empty contents", errOIDInvalidValue},
		{[]byte{1, 0x80}, "object identifier: ber: data truncated: truncated object identifier", errOIDTruncated},
		{[]byte{2, 0x80, 0}, "object identifier: ber: value out of range: invalid object identifier: non-minimal subidentifier at byte 0", errOIDInvalidValue},
	} {
		_, e := DecodeObjectIdentifierAligned(NewBitBufferFromBytes(tc.wire))
		if e == nil || !strings.Contains(e.Error(), tc.want) || !errors.Is(e, tc.classification) || !errors.Is(e, ErrSyntax) {
			t.Fatalf("%x: %v", tc.wire, e)
		}
	}
	if e := EncodeObjectIdentifierAligned(NewBitBuffer(), runtime.ObjectIdentifier{}); e == nil || e.Error() != "object identifier: invalid object identifier" || !errors.Is(e, runtime.ErrInvalidOID) {
		t.Fatal(e)
	}
	oid := runtime.MustObjectIdentifierFromArcs(2, 999, 3)
	bb := NewBitBuffer()
	if e := EncodeObjectIdentifierAligned(bb, oid); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(bb.Bytes(), []byte{3, 0x88, 0x37, 3}) {
		t.Fatalf("OID contents: %x", bb.Bytes())
	}
	decoded, e := DecodeObjectIdentifierAligned(NewBitBufferFromBytes(bb.Bytes()))
	if e != nil || decoded != oid {
		t.Fatalf("OID value: %v %v", decoded, e)
	}
}

func TestPortedAlignmentPolicy(t *testing.T) {
	for _, run := range []func() error{
		func() error {
			return EncodeCollection(NewBitBuffer(), 0, SizeConstraint{Lower: 0, Upper: 0, HasLower: true, HasUpper: true}, false, func(int64, int64) error { return nil })
		},
		func() error {
			_, e := DecodeCollection(NewBitBufferFromBytes([]byte{0}), SizeConstraint{Lower: 0, Upper: 0, HasLower: true, HasUpper: true}, false, func(int64, int64) error { return nil })
			return e
		},
		func() error {
			return EncodeLengthFragments(NewBitBuffer(), 0, false, func(int64, int64) error { return nil })
		},
		func() error {
			_, e := DecodeLengthFragments(NewBitBufferFromBytes([]byte{0}), false, func(int64, int64) error { return nil })
			return e
		},
	} {
		if e := run(); !errors.Is(e, ErrInvalidValue) {
			t.Fatalf("unaligned path: %v", e)
		}
	}
}

func TestPortedGuardDiagnostics(t *testing.T) {
	for _, run := range []func() error{
		func() error { _, e := (&BitBuffer{bitPos: -1}).ReadBit(); return e },
		func() error { return (&BitBuffer{bitPos: -1}).WriteBit(0) },
	} {
		if e := run(); e == nil || e.Error() != "per: value out of range: negative PER bit position -1" {
			t.Fatal(e)
		}
	}
	bb := NewBitBufferFromBytes([]byte{0})
	bb.bitPos = 9
	if _, e := CaptureOpenTypePadding(bb); !errors.Is(e, ErrExtraData) {
		t.Fatal(e)
	}
	if _, e := (&BitBuffer{bitPos: -1}).CompleteBytesWithPadding(CompletePadding{bits: 1, count: 1}); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	bb = NewBitBufferFromBytes([]byte{0})
	bb.bitPos = 1
	if _, e := (&ExtensionAdditions{start: -1}).RecordRecovery(bb, NewBitBuffer(), FinalPadding{}); e == nil || e.Error() != "per: value out of range: invalid recovery start -1 at bit 1" {
		t.Fatal(e)
	}
	if e := validateMinimalUnsigned(nil); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, e := addNonNegativeOffset(math.MaxInt64, 1); !errors.Is(e, ErrInvalidValue) {
		t.Fatal(e)
	}
	if _, _, e := decodeExtensionBitmapBits(NewBitBufferFromBytes([]byte{0}), 8); e == nil || !strings.Contains(e.Error(), "per: data truncated: extension bitmap index 8 exceeds 8 remaining bits") {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		size SizeConstraint
		want string
	}{
		{SizeConstraint{Upper: -1, HasUpper: true}, "per: value out of range: negative SIZE upper bound -1"},
		{SizeConstraint{Lower: 2, Upper: 1, HasLower: true, HasUpper: true}, "per: value out of range: invalid SIZE range [2..1]"},
	} {
		if e := tc.size.validate(); e == nil || e.Error() != tc.want {
			t.Fatal(e)
		}
	}
	if e := EncodeCollection(NewBitBuffer(), 0, SizeConstraint{}, true, nil); e == nil || e.Error() != "per: value out of range: nil collection fragment encoder" {
		t.Fatal(e)
	}
	if e := EncodeLengthFragments(NewBitBuffer(), -1, true, func(int64, int64) error { return nil }); e == nil || e.Error() != "per: value out of range: negative fragmented length -1" {
		t.Fatal(e)
	}
}

func TestPortedNestedCutEligibility(t *testing.T) {
	full := encodeHolder(t, fullHolder(), true)
	parent := NewBitBufferFromBytes(full[:len(full)-1])
	if err := parent.setDecodeSettingsAligned(decodeSettings{TruncatedExtensionTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	child := NewNestedDecodeBuffer(parent.data, parent)
	if _, err := decodeHolder(child, 2, true); !errors.Is(err, ErrTruncated) {
		t.Fatalf("bounded child cut: %v", err)
	}
}

func TestPortedRecoveryReplayEligibility(t *testing.T) {
	cut := &truncatedExtension{input: []byte{0}, bits: 1, expected: []byte{0x80}, expectedBits: 1, recovered: true}
	for _, tc := range []struct {
		value uint64
		width int
		want  bool
	}{{1, 1, true}, {0, 1, false}, {1, 2, false}} {
		bb := NewBitBuffer()
		if err := bb.WriteBits(tc.value, tc.width); err != nil {
			t.Fatal(err)
		}
		if got := cut.follows(bb); got != tc.want {
			t.Fatalf("replay %d/%d = %v", tc.value, tc.width, got)
		}
	}
	bb := NewBitBuffer()
	if err := bb.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	kept := FinalPadding{bits: &finalBits{truncated: cut}}
	AppendExtensionRecovery(bb, kept, -1)
	if bb.BitsWritten() != 1 || bb.Bytes()[0] != 0x80 {
		t.Fatal("invalid span replayed")
	}
	AppendExtensionRecovery(bb, kept, 0)
	if bb.BitsWritten() != 1 || bb.Bytes()[0] != 0 {
		t.Fatal("eligible replay was rejected")
	}
	cut.expectedBits = -1
	if cut.follows(bb) {
		t.Fatal("negative expected span accepted")
	}
}

func TestPortedFragmentRootBound(t *testing.T) {
	calls := 0
	_, err := decodeLengthFragmentsBounded(NewBitBufferFromBytes([]byte{0x80, 0x80}), true, 127, func(int64, int64) error { calls++; return nil })
	if !errors.Is(err, ErrConstraintViolation) || calls != 0 {
		t.Fatalf("first fragment: calls=%d error=%v", calls, err)
	}
	calls = 0
	_, err = decodeLengthFragmentsBounded(NewBitBufferFromBytes([]byte{0xc1, 1}), true, 16384, func(int64, int64) error { calls++; return nil })
	if !errors.Is(err, ErrConstraintViolation) || calls != 1 {
		t.Fatalf("continuation: calls=%d error=%v", calls, err)
	}
}
