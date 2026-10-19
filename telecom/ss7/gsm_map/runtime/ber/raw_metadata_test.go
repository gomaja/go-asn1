// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/raw_metadata_test.go; SHA-256 fce85297337a2fb4715552e0889d4cea7f5b7a756a2e094d44e562a9bf4c07f6.
package ber

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestRawMetadataMustMatchIdentifier(t *testing.T) {
	for _, raw := range []runtime.RawValue{
		{Class: 1, Tag: 5, Bytes: []byte{5, 0}},
		{Tag: 4, Bytes: []byte{5, 0}},
		{Tag: 5, Constructed: true, Bytes: []byte{5, 0}},
		{Bytes: []byte{5, 0}},
	} {
		value := runtime.External{DirectReference: runtime.MustObjectIdentifierFromArcs(1, 2, 3), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: raw}
		for _, options := range [][]EncodeOption{nil, {WithoutBERReplay()}, {WithTolerance(new(ViolationLog))}} {
			if wire, err := EncodeExternal(value, options...); !errors.Is(err, ErrInvalidValue) || wire != nil {
				t.Fatalf("inconsistent raw identifier accepted: %+v: %x %v", raw, wire, err)
			}
		}
		value.RememberBER([]byte{0x28, 8, 6, 2, 0x2a, 3, 0xa0, 2, 5, 0})
		if wire, err := EncodeExternal(value); !errors.Is(err, ErrInvalidValue) || wire != nil {
			t.Fatalf("inconsistent raw metadata escaped through replay: %x %v", wire, err)
		}

		if wire, err := EncodeExternalDER(value); !errors.Is(err, ErrInvalidValue) || wire != nil {
			t.Fatalf("inconsistent DER raw identifier accepted: %+v: %x %v", raw, wire, err)
		}
	}
}
