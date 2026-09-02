package ber

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestDecodeBitStringPrimitiveAndConstructedForms(t *testing.T) {
	primitiveFirst := EncodeBitString([]byte{0x0a, 0x3b}, 0)
	primitiveLast := EncodeBitString([]byte{0x5f, 0x29, 0x1c, 0xd0}, 4)
	definite := EncodeConstructed(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString},
		append(append([]byte(nil), primitiveFirst...), primitiveLast...),
	)
	indefinite := []byte{0x23, 0x80, 0x03, 0x03, 0x00, 0x0a, 0x3b, 0x03, 0x05, 0x04, 0x5f, 0x29, 0x1c, 0xd0, 0x00, 0x00}
	nested := EncodeConstructed(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString},
		append(append([]byte(nil), primitiveFirst...), EncodeConstructed(
			tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString},
			primitiveLast,
		)...),
	)
	empty := EncodeConstructed(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}, nil)

	for _, tc := range []struct {
		name       string
		wire       []byte
		want       []byte
		wantUnused int
	}{
		{name: "primitive", wire: primitiveLast, want: []byte{0x5f, 0x29, 0x1c, 0xd0}, wantUnused: 4},
		{name: "definite constructed", wire: definite, want: []byte{0x0a, 0x3b, 0x5f, 0x29, 0x1c, 0xd0}, wantUnused: 4},
		{name: "indefinite constructed X.690 8.6.4.2", wire: indefinite, want: []byte{0x0a, 0x3b, 0x5f, 0x29, 0x1c, 0xd0}, wantUnused: 4},
		{name: "nested constructed", wire: nested, want: []byte{0x0a, 0x3b, 0x5f, 0x29, 0x1c, 0xd0}, wantUnused: 4},
		{name: "empty constructed", wire: empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, unused, consumed, err := DecodeBitString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(tc.wire) {
				t.Fatalf("consumed = %d, want %d", consumed, len(tc.wire))
			}
			if !bytes.Equal(got, tc.want) || unused != tc.wantUnused {
				t.Fatalf("decoded = %x/%d, want %x/%d", got, unused, tc.want, tc.wantUnused)
			}
		})
	}
}

func TestDecodeConstructedBitStringRejectsInvalidSegments(t *testing.T) {
	bitStringTag := tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}
	for _, tc := range []struct {
		name    string
		wire    []byte
		wantErr error
	}{
		{
			name:    "different child tag",
			wire:    EncodeConstructed(bitStringTag, EncodeOctetString([]byte{0x00, 0xaa})),
			wantErr: ErrInvalidTag,
		},
		{
			name:    "non-final segment has unused bits",
			wire:    EncodeConstructed(bitStringTag, append(EncodeBitString([]byte{0xa0}, 4), EncodeBitString([]byte{0xbb}, 0)...)),
			wantErr: ErrInvalidValue,
		},
		{
			name: "nested non-final segment has unused bits",
			wire: EncodeConstructed(bitStringTag, append(
				EncodeConstructed(bitStringTag, EncodeBitString([]byte{0xa0}, 4)),
				EncodeBitString([]byte{0xbb}, 0)...,
			)),
			wantErr: ErrInvalidValue,
		},
		{
			name:    "truncated child",
			wire:    EncodeConstructed(bitStringTag, []byte{0x03, 0x02, 0x00}),
			wantErr: ErrTruncated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := DecodeBitString(tc.wire); !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeImplicitBitStringValuePreservesConstructedForm(t *testing.T) {
	children := append(EncodeBitString([]byte{0xaa}, 0), EncodeBitString([]byte{0xb0}, 4)...)
	got, unused, err := DecodeImplicitBitStringValue(true, children)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xaa, 0xb0}) || unused != 4 {
		t.Fatalf("constructed value = %x/%d, want aab0/4", got, unused)
	}

	got, unused, err = DecodeImplicitBitStringValue(false, []byte{4, 0xb0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xb0}) || unused != 4 {
		t.Fatalf("primitive value = %x/%d, want b0/4", got, unused)
	}
}

func TestIntegerAndEnumeratedDecodersRejectEachOthersTags(t *testing.T) {
	if _, _, err := DecodeInteger(EncodeEnumerated(1)); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("DecodeInteger(ENUMERATED) error = %v, want ErrInvalidTag", err)
	}
	if _, _, err := DecodeEnumerated(EncodeInteger(1)); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("DecodeEnumerated(INTEGER) error = %v, want ErrInvalidTag", err)
	}
	if got, err := DecodeEnumeratedValue([]byte{0x01}); err != nil || got != 1 {
		t.Fatalf("DecodeEnumeratedValue() = %d, %v, want 1, nil", got, err)
	}
}

func FuzzDecodeBitStringNoPanic(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x03, 0x01, 0x00},
		{0x23, 0x00},
		{0x23, 0x80, 0x00, 0x00},
		{0x23, 0x80, 0x03, 0x01, 0x00, 0x00, 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _, _, _ = DecodeBitString(wire)
	})
}
