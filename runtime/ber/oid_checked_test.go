package ber

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestEncodeOIDValueCheckedValidatesRootArcs(t *testing.T) {
	t.Parallel()

	valid := []struct {
		oid  []uint64
		want []byte
	}{
		{oid: []uint64{0, 0}, want: []byte{0x00}},
		{oid: []uint64{1, 39}, want: []byte{0x4f}},
		{oid: []uint64{2, 999, 3}, want: []byte{0x88, 0x37, 0x03}},
	}
	for _, test := range valid {
		encoded, err := EncodeOIDValueChecked(test.oid)
		if err != nil {
			t.Fatalf("EncodeOIDValueChecked(%v) error = %v", test.oid, err)
		}
		if !bytes.Equal(encoded, test.want) {
			t.Fatalf("EncodeOIDValueChecked(%v) = %x, want %x", test.oid, encoded, test.want)
		}
		decoded, err := DecodeOIDValue(encoded)
		if err != nil {
			t.Fatalf("DecodeOIDValue(%x) error = %v", encoded, err)
		}
		if !reflect.DeepEqual(decoded, test.oid) {
			t.Fatalf("DecodeOIDValue(%x) = %v, want %v", encoded, decoded, test.oid)
		}
	}

	invalid := [][]uint64{
		nil,
		{1},
		{3, 0},
		{0, 40},
		{1, 40},
		{2, math.MaxUint64},
	}
	for _, oid := range invalid {
		if encoded, err := EncodeOIDValueChecked(oid); err == nil || encoded != nil {
			t.Fatalf("EncodeOIDValueChecked(%v) = %x, %v, want rejection", oid, encoded, err)
		}
		if encoded := EncodeOIDValue(oid); encoded != nil {
			t.Fatalf("EncodeOIDValue(%v) = %x, want nil", oid, encoded)
		}
	}
}

func TestRelativeOIDUsesEveryArcAsASubidentifier(t *testing.T) {
	t.Parallel()

	oid := []uint64{8571, 3, 2}
	want := []byte{0xc2, 0x7b, 0x03, 0x02}
	encoded, err := EncodeRelativeOIDValueChecked(oid)
	if err != nil {
		t.Fatalf("EncodeRelativeOIDValueChecked() error = %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("EncodeRelativeOIDValueChecked() = %x, want %x", encoded, want)
	}
	decoded, err := DecodeRelativeOIDValue(encoded)
	if err != nil {
		t.Fatalf("DecodeRelativeOIDValue() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, oid) {
		t.Fatalf("DecodeRelativeOIDValue() = %v, want %v", decoded, oid)
	}
	if encoded, err := EncodeRelativeOIDValueChecked(nil); err == nil || encoded != nil {
		t.Fatalf("EncodeRelativeOIDValueChecked(nil) = %x, %v, want rejection", encoded, err)
	}
}

func TestOIDDecoderRejectsNonCanonicalOrOverflowingSubidentifiers(t *testing.T) {
	t.Parallel()

	for _, value := range [][]byte{
		{0x80, 0x00},
		{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00},
	} {
		if decoded, err := DecodeOIDValue(value); err == nil || decoded != nil {
			t.Fatalf("DecodeOIDValue(%x) = %v, %v, want rejection", value, decoded, err)
		}
	}
}

func TestOIDDecoderClassifiesLoneContinuationAsTruncated(t *testing.T) {
	t.Parallel()

	if _, err := DecodeOIDValue([]byte{0x2a, 0x80}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("DecodeOIDValue() error = %v, want %v", err, ErrTruncated)
	}
}
