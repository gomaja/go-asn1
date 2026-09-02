package per

import (
	"bytes"
	"math"
	"reflect"
	"testing"
)

func TestObjectIdentifierRejectsInvalidRootArcs(t *testing.T) {
	t.Parallel()

	invalid := [][]uint64{{3, 0}, {0, 40}, {1, 40}, {2, math.MaxUint64}}
	for _, oid := range invalid {
		for _, aligned := range []bool{false, true} {
			bb := NewBitBuffer()
			var err error
			if aligned {
				err = EncodeObjectIdentifierAligned(bb, oid)
			} else {
				err = EncodeObjectIdentifier(bb, oid)
			}
			if err == nil {
				t.Fatalf("aligned=%t oid=%v was accepted", aligned, oid)
			}
		}
	}
}

func TestObjectIdentifierUsesX690ContentsInPER(t *testing.T) {
	t.Parallel()

	oid := []uint64{2, 999, 3}
	for _, test := range []struct {
		name   string
		encode func(*BitBuffer, []uint64) error
		decode func(*BitBuffer) ([]uint64, error)
	}{
		{name: "UPER", encode: EncodeObjectIdentifier, decode: DecodeObjectIdentifier},
		{name: "APER", encode: EncodeObjectIdentifierAligned, decode: DecodeObjectIdentifierAligned},
	} {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := test.encode(bb, oid); err != nil {
				t.Fatal(err)
			}
			want := []byte{0x03, 0x88, 0x37, 0x03}
			if !bytes.Equal(bb.Bytes(), want) {
				t.Fatalf("encoded = %x, want %x", bb.Bytes(), want)
			}
			decoded, err := test.decode(NewBitBufferFromBytes(bb.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, oid) {
				t.Fatalf("decoded = %v, want %v", decoded, oid)
			}
		})
	}
}

func TestRelativeObjectIdentifierUsesX690ContentsInPER(t *testing.T) {
	t.Parallel()

	oid := []uint64{8571, 3, 2}
	for _, test := range []struct {
		name   string
		encode func(*BitBuffer, []uint64) error
		decode func(*BitBuffer) ([]uint64, error)
	}{
		{name: "UPER", encode: EncodeRelativeObjectIdentifier, decode: DecodeRelativeObjectIdentifier},
		{name: "APER", encode: EncodeRelativeObjectIdentifierAligned, decode: DecodeRelativeObjectIdentifierAligned},
	} {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := test.encode(bb, oid); err != nil {
				t.Fatal(err)
			}
			want := []byte{0x04, 0xc2, 0x7b, 0x03, 0x02}
			if !bytes.Equal(bb.Bytes(), want) {
				t.Fatalf("encoded = %x, want %x", bb.Bytes(), want)
			}
			decoded, err := test.decode(NewBitBufferFromBytes(bb.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, oid) {
				t.Fatalf("decoded = %v, want %v", decoded, oid)
			}
		})
	}
}
