package per

import (
	"bytes"
	"errors"
	"math"
	"reflect"
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
	for _, aligned := range []bool{false, true} {
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
							return EncodeOctetString(bb, data, 0, 0, false)
						},
						decode: func(bb *BitBuffer) ([]byte, error) {
							if aligned {
								return DecodeOctetStringAligned(bb, 0, 0, false)
							}
							return DecodeOctetString(bb, 0, 0, false)
						},
					},
					{
						name: "open-type",
						encode: func(bb *BitBuffer, data []byte) error {
							if aligned {
								return EncodeOpenTypeAligned(bb, data)
							}
							return EncodeOpenType(bb, data)
						},
						decode: func(bb *BitBuffer) ([]byte, error) {
							if aligned {
								return DecodeOpenTypeAligned(bb)
							}
							return DecodeOpenType(bb)
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
		if err := EncodeOctetString(bb, make([]byte, length), 0, 0, false); err != nil {
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
	for _, aligned := range []bool{false, true} {
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
				err = EncodeBitString(bb, value, bitLength, 0, 0, false)
			}
			if err != nil {
				t.Fatalf("encode aligned=%v length=%d: %v", aligned, bitLength, err)
			}
			var got []byte
			var gotLength int
			if aligned {
				got, gotLength, err = DecodeBitStringAligned(NewBitBufferFromBytes(bb.Bytes()), 0, 0, false)
			} else {
				got, gotLength, err = DecodeBitString(NewBitBufferFromBytes(bb.Bytes()), 0, 0, false)
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

func equalSignificantBits(left, right []byte, bitLength int) bool {
	byteLength := (bitLength + 7) / 8
	if len(left) != byteLength || len(right) < byteLength {
		return false
	}
	if bitLength%8 == 0 {
		return bytes.Equal(left, right[:byteLength])
	}
	last := byteLength - 1
	if !bytes.Equal(left[:last], right[:last]) {
		return false
	}
	mask := byte(0xff << (8 - bitLength%8))
	return left[last]&mask == right[last]&mask
}

func TestFragmentedKnownMultiplierStringRoundTrip(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		for _, length := range []int{perFragmentUnit - 1, perFragmentUnit, 4 * perFragmentUnit, 4*perFragmentUnit + 1} {
			value := strings.Repeat("A", length)
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeKnownMultiplierStringAligned(bb, value, 7, 0, 0, false)
			} else {
				err = EncodeKnownMultiplierString(bb, value, 7, 0, 0, false)
			}
			if err != nil {
				t.Fatalf("encode aligned=%v length=%d: %v", aligned, length, err)
			}
			var got string
			if aligned {
				got, err = DecodeKnownMultiplierStringAligned(NewBitBufferFromBytes(bb.Bytes()), 7, 0, 0, false)
			} else {
				got, err = DecodeKnownMultiplierString(NewBitBufferFromBytes(bb.Bytes()), 7, 0, 0, false)
			}
			if err != nil {
				t.Fatalf("decode aligned=%v length=%d: %v", aligned, length, err)
			}
			if got != value {
				t.Fatalf("round trip length = %d, want %d", len(got), len(value))
			}
		}
	}
}

func TestLengthDelimitedWideStringRejectsOutOfRangeRuneBeforeMutation(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeKnownMultiplierStringAligned(bb, "\U0001f600", 16, 0, 0, false)
		} else {
			err = EncodeKnownMultiplierString(bb, "\U0001f600", 16, 0, 0, false)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("aligned=%v error = %v, want ErrConstraintViolation", aligned, err)
		}
		if bb.BitPos() != 0 {
			t.Fatalf("aligned=%v encoder mutated buffer: bit position = %d", aligned, bb.BitPos())
		}
	}
}

func TestFragmentedObjectIdentifiersRoundTrip(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		relative := make([]uint64, perFragmentUnit)
		absolute := make([]uint64, perFragmentUnit+2)
		absolute[0], absolute[1] = 1, 2
		for _, tc := range []struct {
			name   string
			value  []uint64
			encode func(*BitBuffer, []uint64) error
			decode func(*BitBuffer) ([]uint64, error)
		}{
			{
				name:  "object-identifier",
				value: absolute,
				encode: func(bb *BitBuffer, value []uint64) error {
					if aligned {
						return EncodeObjectIdentifierAligned(bb, value)
					}
					return EncodeObjectIdentifier(bb, value)
				},
				decode: func(bb *BitBuffer) ([]uint64, error) {
					if aligned {
						return DecodeObjectIdentifierAligned(bb)
					}
					return DecodeObjectIdentifier(bb)
				},
			},
			{
				name:  "relative-oid",
				value: relative,
				encode: func(bb *BitBuffer, value []uint64) error {
					if aligned {
						return EncodeRelativeObjectIdentifierAligned(bb, value)
					}
					return EncodeRelativeObjectIdentifier(bb, value)
				},
				decode: func(bb *BitBuffer) ([]uint64, error) {
					if aligned {
						return DecodeRelativeObjectIdentifierAligned(bb)
					}
					return DecodeRelativeObjectIdentifier(bb)
				},
			},
		} {
			t.Run(map[bool]string{false: "uper", true: "aper"}[aligned]+"/"+tc.name, func(t *testing.T) {
				bb := NewBitBuffer()
				if err := tc.encode(bb, tc.value); err != nil {
					t.Fatal(err)
				}
				got, err := tc.decode(NewBitBufferFromBytes(bb.Bytes()))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, tc.value) {
					t.Fatalf("round trip arc count = %d, want %d", len(got), len(tc.value))
				}
			})
		}
	}
}

func TestFragmentedLengthRejectsMalformedDeterminants(t *testing.T) {
	fragment := make([]byte, perFragmentUnit)
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{name: "non-minimal long form", wire: []byte{0x80, 0x7f}},
		{name: "zero multiplier", wire: []byte{0xc0}},
		{name: "multiplier above four", wire: []byte{0xc5}},
		{name: "truncated fragment", wire: []byte{0xc1}},
		{name: "missing terminal determinant", wire: append([]byte{0xc1}, fragment...)},
		{name: "non-maximal prior fragment", wire: append(append(append([]byte{0xc1}, fragment...), 0xc1), fragment...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeOctetString(NewBitBufferFromBytes(tc.wire), 0, 0, false)
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
	for _, aligned := range []bool{false, true} {
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
	for _, aligned := range []bool{false, true} {
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

func TestFragmentedRootUpperBoundRejectsBeforeOversizedPayload(t *testing.T) {
	const upper = int64(4 * perFragmentUnit)
	for _, aligned := range []bool{false, true} {
		for _, tc := range []struct {
			name                string
			bitsPerFragmentUnit int
			decode              func(*BitBuffer) error
		}{
			{
				name:                "octet-string",
				bitsPerFragmentUnit: 8,
				decode: func(bb *BitBuffer) error {
					if aligned {
						_, err := DecodeOctetStringAligned(bb, 0, upper, true)
						return err
					}
					_, err := DecodeOctetString(bb, 0, upper, true)
					return err
				},
			},
			{
				name:                "bit-string",
				bitsPerFragmentUnit: 1,
				decode: func(bb *BitBuffer) error {
					if aligned {
						_, _, err := DecodeBitStringAligned(bb, 0, upper, true)
						return err
					}
					_, _, err := DecodeBitString(bb, 0, upper, true)
					return err
				},
			},
			{
				name:                "character-string",
				bitsPerFragmentUnit: 7,
				decode: func(bb *BitBuffer) error {
					if aligned {
						_, err := DecodeKnownMultiplierStringAligned(bb, 7, 0, upper, true)
						return err
					}
					_, err := DecodeKnownMultiplierString(bb, 7, 0, upper, true)
					return err
				},
			},
		} {
			t.Run(map[bool]string{false: "uper", true: "aper"}[aligned]+"/"+tc.name, func(t *testing.T) {
				firstPayloadBytes := 4 * perFragmentUnit * tc.bitsPerFragmentUnit / 8
				secondPayloadBytes := perFragmentUnit * tc.bitsPerFragmentUnit / 8
				wire := make([]byte, 0, 3+firstPayloadBytes+secondPayloadBytes)
				wire = append(wire, 0xc4)
				wire = append(wire, make([]byte, firstPayloadBytes)...)
				wire = append(wire, 0xc1)
				beforeOversizedPayload := len(wire) * 8
				wire = append(wire, make([]byte, secondPayloadBytes)...)
				wire = append(wire, 0)

				bb := NewBitBufferFromBytes(wire)
				if err := tc.decode(bb); !errors.Is(err, ErrConstraintViolation) {
					t.Fatalf("decode error = %v, want ErrConstraintViolation", err)
				}
				if bb.BitPos() != beforeOversizedPayload {
					t.Fatalf("decoder consumed oversized payload: bit position = %d, want %d", bb.BitPos(), beforeOversizedPayload)
				}
			})
		}
	}
}

func TestFixed64KValuesUseFragmentation(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			encode func(*BitBuffer) error
		}{
			{
				name: "octet-string",
				encode: func(bb *BitBuffer) error {
					if aligned {
						return EncodeOctetStringAligned(bb, make([]byte, 4*perFragmentUnit), 4*perFragmentUnit, 4*perFragmentUnit, true)
					}
					return EncodeOctetString(bb, make([]byte, 4*perFragmentUnit), 4*perFragmentUnit, 4*perFragmentUnit, true)
				},
			},
			{
				name: "bit-string",
				encode: func(bb *BitBuffer) error {
					if aligned {
						return EncodeBitStringAligned(bb, make([]byte, perFragmentUnit/2), 4*perFragmentUnit, 4*perFragmentUnit, 4*perFragmentUnit, true)
					}
					return EncodeBitString(bb, make([]byte, perFragmentUnit/2), 4*perFragmentUnit, 4*perFragmentUnit, 4*perFragmentUnit, true)
				},
			},
			{
				name: "character-string",
				encode: func(bb *BitBuffer) error {
					value := strings.Repeat("A", 4*perFragmentUnit)
					if aligned {
						return EncodeKnownMultiplierStringAligned(bb, value, 7, 4*perFragmentUnit, 4*perFragmentUnit, true)
					}
					return EncodeKnownMultiplierString(bb, value, 7, 4*perFragmentUnit, 4*perFragmentUnit, true)
				},
			},
		} {
			t.Run(map[bool]string{false: "uper", true: "aper"}[aligned]+"/"+tc.name, func(t *testing.T) {
				bb := NewBitBuffer()
				if err := tc.encode(bb); err != nil {
					t.Fatal(err)
				}
				if bb.Bytes()[0] != 0xc4 {
					t.Fatalf("first determinant = %02x, want c4", bb.Bytes()[0])
				}
			})
		}
	}
}

func Test64KUpperBoundUsesUnconstrainedLengthForm(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		bb := NewBitBuffer()
		var err error
		if aligned {
			err = EncodeOctetStringAligned(bb, []byte{0x5a}, 0, 64*1024, true)
		} else {
			err = EncodeOctetString(bb, []byte{0x5a}, 0, 64*1024, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := bb.Bytes(); !bytes.Equal(got, []byte{0x01, 0x5a}) {
			t.Fatalf("aligned=%v wire = %x, want 015a", aligned, got)
		}
	}
}

func FuzzFragmentedValueDecodersNoPanic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0xc0})
	f.Add([]byte{0xc1})
	f.Add([]byte{0x80, 0x7f})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, decode := range []func(*BitBuffer) error{
			func(bb *BitBuffer) error { _, err := DecodeOctetString(bb, 0, 0, false); return err },
			func(bb *BitBuffer) error { _, err := DecodeOctetStringAligned(bb, 0, 0, false); return err },
			func(bb *BitBuffer) error { _, _, err := DecodeBitString(bb, 0, 0, false); return err },
			func(bb *BitBuffer) error { _, _, err := DecodeBitStringAligned(bb, 0, 0, false); return err },
			func(bb *BitBuffer) error { _, err := DecodeKnownMultiplierString(bb, 7, 0, 0, false); return err },
			func(bb *BitBuffer) error {
				_, err := DecodeKnownMultiplierStringAligned(bb, 7, 0, 0, false)
				return err
			},
			func(bb *BitBuffer) error { _, err := DecodeOpenType(bb); return err },
			func(bb *BitBuffer) error { _, err := DecodeOpenTypeAligned(bb); return err },
		} {
			_ = decode(NewBitBufferFromBytes(data))
		}
	})
}
