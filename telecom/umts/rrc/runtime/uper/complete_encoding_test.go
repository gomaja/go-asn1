// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/complete_encoding_test.go; SHA-256 803b561fafa986236e25495f580c9f3b15db796b0ce5773cf90fa1842d696ab7.
package uper

import (
	"bytes"
	"errors"
	"testing"
)

func TestCompleteBytesRepresentsZeroBitEncoding(t *testing.T) {
	bb := NewBitBuffer()
	if got := bb.CompleteBytes(); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("zero-bit complete encoding = %x, want 00", got)
	}

	if err := bb.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	if got := bb.CompleteBytes(); !bytes.Equal(got, []byte{0x80}) {
		t.Fatalf("one-bit complete encoding = %x, want 80", got)
	}
}

func TestCompleteEncodingPaddingAcceptsZeroBitValue(t *testing.T) {
	for _, validate := range []struct {
		name string
		run  func(*BitBuffer) error
	}{
		{name: "top-level", run: ValidateFinalPadding},
		{name: "open-type", run: ValidateOpenTypePadding},
	} {
		t.Run(validate.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{0})
			if err := validate.run(bb); err != nil {
				t.Fatalf("zero-bit complete encoding rejected: %v", err)
			}
			if bb.BitsRemaining() != 0 {
				t.Fatalf("bits remaining = %d, want 0", bb.BitsRemaining())
			}
		})
	}
}

func TestCompleteEncodingPaddingRejectsMalformedZeroBitValues(t *testing.T) {
	for _, validate := range []struct {
		name string
		run  func(*BitBuffer) error
	}{
		{name: "top-level", run: ValidateFinalPadding},
		{name: "open-type", run: ValidateOpenTypePadding},
	} {
		t.Run(validate.name, func(t *testing.T) {
			for _, test := range []struct {
				name string
				wire []byte
				want error
			}{
				{name: "missing", want: ErrTruncated},
				{name: "non-zero", wire: []byte{1}, want: ErrInvalidValue},
				{name: "appended-octet", wire: []byte{0, 0}, want: ErrExtraData},
			} {
				t.Run(test.name, func(t *testing.T) {
					err := validate.run(NewBitBufferFromBytes(test.wire))
					if !errors.Is(err, test.want) {
						t.Fatalf("error = %v, want %v", err, test.want)
					}
				})
			}
		})
	}
}

func FuzzZeroBitCompleteEncodingValidation(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		for _, validate := range []func(*BitBuffer) error{ValidateFinalPadding, ValidateOpenTypePadding} {
			bb := NewBitBufferFromBytes(wire)
			err := validate(bb)
			if bytes.Equal(wire, []byte{0}) {
				if err != nil {
					t.Fatalf("canonical zero-bit complete encoding rejected: %v", err)
				}
				if bb.BitsRemaining() != 0 {
					t.Fatalf("canonical encoding left %d bits", bb.BitsRemaining())
				}
			} else if err == nil {
				t.Fatalf("noncanonical zero-bit complete encoding accepted: %x", wire)
			}
		}
	})
}
