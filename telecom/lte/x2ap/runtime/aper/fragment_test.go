// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/fragment_test.go; SHA-256 7eeccee77d16ec1f1561af8dcb5a710497afdb8ef629b7861a758c3f0e9ac246.
package aper

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestBitLengthValidationDoesNotOverflow(t *testing.T) {
	bb := NewBitBuffer()
	if err := bb.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), bb.Bytes()...)
	beforeBits := bb.BitsWritten()
	if err := encodeLengthDelimitedBits(bb, nil, math.MaxInt, false); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("encode error = %v, want ErrInvalidValue", err)
	}
	if !bytes.Equal(bb.Bytes(), before) || bb.BitsWritten() != beforeBits {
		t.Fatal("encoder mutated the buffer for an impossible source length")
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("WriteBitsFromBytes panicked: %v", recovered)
		}
	}()
	if err := bb.WriteBitsFromBytes(nil, math.MaxInt); err == nil {
		t.Fatal("WriteBitsFromBytes accepted an impossible source length")
	}
}

func TestFragmentedOctetAndOpenTypeRoundTrip(t *testing.T) {
	for _, aligned := range []bool{true} {
		for _, length := range []int{perFragmentUnit - 1, perFragmentUnit, 4 * perFragmentUnit, 4*perFragmentUnit + 1, 5*perFragmentUnit + 17} {
			name := map[bool]string{false: "uper", true: "aper"}[aligned]
			t.Run(name+"/length_"+strconv.Itoa(length), func(t *testing.T) {
				value := make([]byte, length)
				for index := range value {
					value[index] = byte(index)
				}
				for _, codec := range []struct {
					name   string
					encode func(*BitBuffer, []byte) error
					decode func(*BitBuffer) ([]byte, error)
				}{
					{
						name: "octet-string",
						encode: func(bb *BitBuffer, data []byte) error {
							if aligned {
								return EncodeOctetStringAligned(bb, data, 0, 0, false)
							}
							return EncodeOctetStringAligned(bb, data, 0, 0, false)
						},
						decode: func(bb *BitBuffer) ([]byte, error) {
							if aligned {
								return DecodeOctetStringAligned(bb, 0, 0, false)
							}
							return DecodeOctetStringAligned(bb, 0, 0, false)
						},
					},
					{
						name: "open-type",
						encode: func(bb *BitBuffer, data []byte) error {
							if aligned {
								return EncodeOpenTypeAligned(bb, data)
							}
							return EncodeOpenTypeAligned(bb, data)
						},
						decode: func(bb *BitBuffer) ([]byte, error) {
							if aligned {
								return DecodeOpenTypeAligned(bb)
							}
							return DecodeOpenTypeAligned(bb)
						},
					},
				} {
					t.Run(codec.name, func(t *testing.T) {
						bb := NewBitBuffer()
						if err := codec.encode(bb, value); err != nil {
							t.Fatal(err)
						}
						got, err := codec.decode(NewBitBufferFromBytes(bb.Bytes()))
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got, value) {
							t.Fatalf("round trip length = %d, want %d", len(got), len(value))
						}
					})
				}
			})
		}
	}
}

func TestFragmentedOctetStringWireDeterminants(t *testing.T) {
	for _, length := range []int{perFragmentUnit, 4 * perFragmentUnit, 4*perFragmentUnit + 1, 5 * perFragmentUnit} {
		bb := NewBitBuffer()
		if err := EncodeOctetStringAligned(bb, make([]byte, length), 0, 0, false); err != nil {
			t.Fatal(err)
		}
		wire := bb.Bytes()
		firstMultiplier := length / perFragmentUnit
		if firstMultiplier > 4 {
			firstMultiplier = 4
		}
		if wire[0] != byte(0xc0|firstMultiplier) {
			t.Fatalf("length %d first determinant = %02x, want %02x", length, wire[0], 0xc0|firstMultiplier)
		}
		firstEnd := 1 + firstMultiplier*perFragmentUnit
		if length == firstMultiplier*perFragmentUnit {
			if len(wire) <= firstEnd {
				t.Fatalf("length %d omitted terminal determinant", length)
			}
			if wire[firstEnd] != 0 {
				t.Fatalf("length %d terminal determinant = %02x, want 00", length, wire[firstEnd])
			}
		}
	}
}

func TestFragmentedBitStringRoundTrip(t *testing.T) {
	for _, aligned := range []bool{true} {
		for _, bitLength := range []int{perFragmentUnit - 1, perFragmentUnit, 4 * perFragmentUnit, 4*perFragmentUnit + 1} {
			value := make([]byte, (bitLength+7)/8)
			for index := range value {
				value[index] = byte(index*31 + 7)
			}
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeBitStringAligned(bb, value, bitLength, 0, 0, false)
			} else {
				err = EncodeBitStringAligned(bb, value, bitLength, 0, 0, false)
			}
			if err != nil {
				t.Fatalf("encode aligned=%v length=%d: %v", aligned, bitLength, err)
			}
			var got []byte
			var gotLength int
			if aligned {
				got, gotLength, err = DecodeBitStringAligned(NewBitBufferFromBytes(bb.Bytes()), 0, 0, false)
			} else {
				got, gotLength, err = DecodeBitStringAligned(NewBitBufferFromBytes(bb.Bytes()), 0, 0, false)
			}
			if err != nil {
				t.Fatalf("decode aligned=%v length=%d: %v", aligned, bitLength, err)
			}
			if gotLength != bitLength || !equalSignificantBits(got, value, bitLength) {
				t.Fatalf("round trip aligned=%v length = %d, want %d", aligned, gotLength, bitLength)
			}
		}
	}
}

func TestFragmentedLengthRejectsMalformedDeterminants(t *testing.T) {
	fragment := make([]byte, perFragmentUnit)
	for _, tc := range []struct {
		name   string
		wire   []byte
		clause string
	}{
		{name: "non-minimal long form", clause: "§11.9.3.6", wire: []byte{0x80, 0x7f}},
		{name: "zero multiplier", clause: "§11.9.3.8", wire: []byte{0xc0}},
		{name: "multiplier above four", clause: "§11.9.3.8", wire: []byte{0xc5}},
		{name: "truncated fragment", clause: "§11.9.3.8.2", wire: []byte{0xc1}},
		{name: "missing terminal determinant", clause: "§11.9.3.8.3", wire: append([]byte{0xc1}, fragment...)},
		{name: "non-maximal prior fragment", clause: "§11.9.3.8.1", wire: append(append(append([]byte{0xc1}, fragment...), 0xc1), fragment...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeOctetStringAligned(NewBitBufferFromBytes(tc.wire), 0, 0, false)
			var located *DecodeError
			if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != tc.clause || !located.Location.HasWireLocation {
				t.Fatalf("rule/location: %v %+v", err, located)
			}
			if err == nil {
				t.Fatal("malformed determinant accepted")
			}
			if strings.Contains(tc.name, "truncated") || strings.Contains(tc.name, "missing terminal") {
				if !errors.Is(err, ErrTruncated) {
					t.Fatalf("error = %v, want ErrTruncated", err)
				}
			} else if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

func TestFragmentedCollectionCallbacksInterleavePayload(t *testing.T) {
	const count = perFragmentUnit + 1
	for _, aligned := range []bool{true} {
		bb := NewBitBuffer()
		if err := EncodeCollection(bb, count, SizeConstraint{}, aligned, func(offset, length int64) error {
			for index := int64(0); index < length; index++ {
				if err := EncodeBoolean(bb, (offset+index)%2 != 0); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		wire := bb.Bytes()
		if wire[0] != 0xc1 {
			t.Fatalf("aligned=%v first determinant = %02x, want c1", aligned, wire[0])
		}
		terminalOffset := 1 + perFragmentUnit/8
		if wire[terminalOffset] != 1 {
			t.Fatalf("aligned=%v terminal determinant = %02x, want 01", aligned, wire[terminalOffset])
		}

		reader := NewBitBufferFromBytes(wire)
		var decoded int64
		total, err := DecodeCollection(reader, SizeConstraint{}, aligned, func(offset, length int64) error {
			if offset != decoded {
				return errors.New("non-contiguous collection callback")
			}
			for index := int64(0); index < length; index++ {
				value, err := DecodeBoolean(reader)
				if err != nil {
					return err
				}
				if value != ((offset+index)%2 != 0) {
					return errors.New("collection element mismatch")
				}
			}
			decoded += length
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if total != count || decoded != count {
			t.Fatalf("aligned=%v decoded = %d/%d, want %d", aligned, total, decoded, count)
		}
	}
}

func TestCollectionLargeRootAndExtensionConstraints(t *testing.T) {
	for _, aligned := range []bool{true} {
		for _, tc := range []struct {
			name       string
			count      int64
			lower      int64
			upper      int64
			extensible bool
		}{
			{name: "large root", count: perFragmentUnit, lower: 1, upper: 70000, extensible: true},
			{name: "extension", count: perFragmentUnit, lower: 1, upper: 4, extensible: true},
			{name: "fixed 64K", count: 4 * perFragmentUnit, lower: 4 * perFragmentUnit, upper: 4 * perFragmentUnit},
		} {
			t.Run(map[bool]string{false: "uper", true: "aper"}[aligned]+"/"+tc.name, func(t *testing.T) {
				bb := NewBitBuffer()
				size := SizeConstraint{Lower: tc.lower, Upper: tc.upper, HasLower: true, HasUpper: true, Extensible: tc.extensible}
				if err := EncodeCollection(bb, tc.count, size, aligned, func(_, _ int64) error { return nil }); err != nil {
					t.Fatal(err)
				}
				total, err := DecodeCollection(NewBitBufferFromBytes(bb.Bytes()), size, aligned, func(_, _ int64) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				if total != tc.count {
					t.Fatalf("decoded count = %d, want %d", total, tc.count)
				}
			})
		}
	}
}

func Test64KUpperBoundUsesUnconstrainedLengthForm(t *testing.T) {
	for _, aligned := range []bool{true} {
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeOctetStringAligned(bb, []byte{0x5a}, 0, 64*1024, true)
		} else {
			err = EncodeOctetStringAligned(bb, []byte{0x5a}, 0, 64*1024, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := bb.Bytes(); !bytes.Equal(got, []byte{0x01, 0x5a}) {
			t.Fatalf("aligned=%v wire = %x, want 015a", aligned, got)
		}
	}
}
