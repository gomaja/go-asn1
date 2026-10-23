// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/integer_set_test.go; SHA-256 47ac85c2635f6ac933d62ac7521217f2746a29a82f240edb303ed29b24da1552.
package uper

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestBitStringExtUPERRoundTrip(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		data   []byte
		bitLen int
	}{
		{name: "root", data: []byte{0xa0}, bitLen: 3},
		{name: "extension", data: []byte{0xab, 0xc0}, bitLen: 10},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bb := NewBitBuffer()
			if err := EncodeBitStringExt(bb, test.data, test.bitLen, 1, 8, true, true); err != nil {
				t.Fatalf("EncodeBitStringExt() error = %v", err)
			}
			gotData, gotBitLen, err := DecodeBitStringExt(NewBitBufferFromBytes(bb.Bytes()), 1, 8, true, true)
			if err != nil {
				t.Fatalf("DecodeBitStringExt() error = %v", err)
			}
			if gotBitLen != test.bitLen || !bytes.Equal(gotData, test.data) {
				t.Fatalf("DecodeBitStringExt() = %x/%d, want %x/%d", gotData, gotBitLen, test.data, test.bitLen)
			}
		})
	}
}

func TestSignedConstrainedWholeNumberFullRange(t *testing.T) {
	t.Parallel()

	for _, aligned := range []bool{false} {
		_ = aligned
		for _, value := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
			bb := NewBitBuffer()
			var err error

			{
				err = EncodeConstrainedWholeNumber(bb, value, math.MinInt64, math.MaxInt64)
			}
			if err != nil {
				t.Fatalf("encode aligned=%v value=%d: %v", aligned, value, err)
			}
			reader := NewBitBufferFromBytes(bb.Bytes())
			var got int64

			{
				got, err = DecodeConstrainedWholeNumber(reader, math.MinInt64, math.MaxInt64)
			}
			if err != nil || got != value {
				t.Fatalf("decode aligned=%v value=%d = %d, %v", aligned, value, got, err)
			}
		}
	}
}

func TestExtensibleSizeEncodersRejectInvertedRootBeforeMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		encode func(*BitBuffer) error
	}{
		{name: "UPER BIT STRING", encode: func(bb *BitBuffer) error { return EncodeBitStringExt(bb, nil, 0, 2, 1, true, true) }},
		{name: "UPER OCTET STRING", encode: func(bb *BitBuffer) error { return EncodeOctetStringExt(bb, nil, 2, 1, true, true) }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bb := NewBitBuffer()
			if err := bb.WriteBits(5, 3); err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), bb.Bytes()...)
			beforeBits := bb.BitsWritten()
			if err := test.encode(bb); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("encode error = %v, want %v", err, ErrInvalidValue)
			}
			if !bytes.Equal(bb.Bytes(), before) || bb.BitsWritten() != beforeBits {
				t.Fatalf("encoder mutated buffer: bytes=%x bits=%d, want %x/%d", bb.Bytes(), bb.BitsWritten(), before, beforeBits)
			}
		})
	}
}
