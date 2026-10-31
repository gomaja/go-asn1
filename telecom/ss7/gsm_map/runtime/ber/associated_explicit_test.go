// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/associated_explicit_test.go; SHA-256 05b7d5a9666aaf31b805d1bdb6fc3e82e396517ee1c3033541ac947dca1b5af2.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// X.690 (02/2021) §8.18.1 and X.680 (02/2021) §31.2.7 b)
// make single-ASN1-type explicit. X.680 §§36.5, 44.5, 31.2.7 c)
// make identification explicit; X.690 §§8.14.3, 8.17.1, 8.24.1 encode it.
func TestAssociatedExplicitForm(t *testing.T) {
	for _, row := range []struct {
		name, wire string
		want       error
	}{
		{"external primitive", "280706032a03048000", ErrInvalidTag},
		{"external primitive indefinite", "280906032a030480800000", ErrInvalidLength},
		{"external indefinite", "288006032a030480000000", ErrInvalidTag},
		{"external constructed indefinite", "288006032a0304a080050000000000", nil},
		{"external constructed", "280906032a0304a0020500", nil},
		{"nested external", "3009280706032a03048000", ErrInvalidTag},
		{"embedded primitive identification", "2b0480008200", ErrInvalidTag},
		{"embedded constructed identification", "2b06a00285008200", nil},
		{"character primitive identification", "3d0480008200", ErrInvalidTag},
		{"character constructed identification", "3d06a00285008200", nil},
		{"unrelated context zero", "30028000", nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, opts := range [][]DecodeOption{nil, {WithTolerance(new(ViolationLog))}} {
				err = ValidateBERElement(wire, opts...)
				if row.want == nil && err != nil {
					t.Fatal(err)
				}
				for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit, ErrInvalidCodec, ErrInvalidBinding} {
					if errors.Is(err, sentinel) != (sentinel == row.want) {
						t.Fatalf("scan=%v errors.Is(%v), want=%v", err, sentinel, row.want)
					}
				}
			}
		})
	}
}

// X.690 (02/2021) §§8.14.3, 8.18.1: generic and typed EXTERNAL
// entry points agree on the explicit choice, including tolerant decoding.
func TestExternalExplicitEncodingControls(t *testing.T) {
	for _, row := range []struct {
		wire string
		want error
	}{
		{"280706032a03048000", ErrInvalidTag},
		{"280906032a0304a0020500", nil},
	} {
		data, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, opts := range [][]DecodeOption{nil, {WithTolerance(new(ViolationLog))}} {
			value, used, err := DecodeExternal(data, opts...)
			for _, sent := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit, ErrInvalidCodec, ErrInvalidBinding} {
				if errors.Is(err, sent) != (sent == row.want) {
					t.Fatalf("%x: %v errors.Is(%v), want %v", data, err, sent, row.want)
				}
			}
			if row.want != nil {
				continue
			}
			if err != nil || used != len(data) {
				t.Fatalf("decode consumed %d: %v", used, err)
			}
			out, err := EncodeExternal(value)
			if err != nil || !bytes.Equal(out, data) {
				t.Fatalf("replay %x: %v", out, err)
			}
		}
	}
}
