package per

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func TestObjectIdentifierRejectsInvalidRootArcs(t *testing.T) {
	for _, arcs := range [][]uint64{{3, 0}, {0, 40}, {1, 40}} {
		if _, err := runtime.ObjectIdentifierFromArcs(arcs...); err == nil {
			t.Fatal(arcs)
		}
	}
	for _, enc := range []func(*BitBuffer, runtime.ObjectIdentifier) error{EncodeObjectIdentifier, EncodeObjectIdentifierAligned} {
		if err := enc(NewBitBuffer(), runtime.ObjectIdentifier{}); err == nil {
			t.Fatal("accepted zero")
		}
	}
}
func TestObjectIdentifierUsesX690ContentsInPER(t *testing.T) {
	oid := runtime.MustObjectIdentifierFromArcs(2, 999, 3)
	for _, test := range []struct {
		name   string
		encode func(*BitBuffer, runtime.ObjectIdentifier) error
		decode func(*BitBuffer) (runtime.ObjectIdentifier, error)
	}{
		{"UPER", EncodeObjectIdentifier, DecodeObjectIdentifier}, {"APER", EncodeObjectIdentifierAligned, DecodeObjectIdentifierAligned},
	} {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := test.encode(bb, oid); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.Bytes(), []byte{3, 0x88, 0x37, 3}) {
				t.Fatalf("%x", bb.Bytes())
			}
			got, err := test.decode(NewBitBufferFromBytes(bb.Bytes()))
			if err != nil || got != oid {
				t.Fatalf("%v %v", got, err)
			}
		})
	}
}
func TestRelativeObjectIdentifierUsesX690ContentsInPER(t *testing.T) {
	oid := runtime.MustRelativeObjectIdentifierFromArcs(8571, 3, 2)
	for _, test := range []struct {
		name   string
		encode func(*BitBuffer, runtime.RelativeObjectIdentifier) error
		decode func(*BitBuffer) (runtime.RelativeObjectIdentifier, error)
	}{
		{"UPER", EncodeRelativeObjectIdentifier, DecodeRelativeObjectIdentifier}, {"APER", EncodeRelativeObjectIdentifierAligned, DecodeRelativeObjectIdentifierAligned},
	} {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := test.encode(bb, oid); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.Bytes(), []byte{4, 0xc2, 0x7b, 3, 2}) {
				t.Fatalf("%x", bb.Bytes())
			}
			got, err := test.decode(NewBitBufferFromBytes(bb.Bytes()))
			if err != nil || got != oid {
				t.Fatalf("%v %v", got, err)
			}
		})
	}
}
