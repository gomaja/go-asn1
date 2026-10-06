package ber

import (
	"errors"
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func TestDecodeResourceErrorFamily(t *testing.T) {
	leaf := []byte{4, 1, 42}
	depth := []byte{0x30, 0x80, 0x30, 0x80, 0x30, 0x80, 4, 1, 42, 0, 0, 0, 0, 0, 0}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"REAL comparison work", func() error {
			_, e := boundedRealRat(runtime.Real{Base: 10, Mantissa: big.NewInt(1), Exponent: big.NewInt(1_000_001)})
			return e
		}},
		{"TLV work", func() error { _, _, _, e := DecodeTLV(leaf, WithDecodeLimits(DecodeLimits{MaxWork: 2})); return e }},
		{"TLV scan depth", func() error { _, _, _, e := DecodeTLV(depth, WithDecodeLimits(DecodeLimits{MaxDepth: 1})); return e }},
		{"TLV scan elements", func() error { _, _, _, e := DecodeTLV(depth, WithDecodeLimits(DecodeLimits{MaxElements: 1})); return e }},
		{"validator work", func() error { return ValidateBERElement(leaf, WithDecodeLimits(DecodeLimits{MaxWork: 2})) }},
		{"validator depth", func() error { return ValidateBERElement(depth, WithDecodeLimits(DecodeLimits{MaxDepth: 1})) }},
		{"validator elements", func() error { return ValidateBERElement(depth, WithDecodeLimits(DecodeLimits{MaxElements: 1})) }},
		{"children elements", func() error {
			_, e := DecodeSequenceChildren(append(leaf, leaf...), WithDecodeLimits(DecodeLimits{MaxElements: 1}))
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.run()
			if !errors.Is(e, ErrResourceLimit) || errors.Is(e, ErrInvalidValue) {
				t.Fatalf("got %v; want only ErrResourceLimit", e)
			}
		})
	}
}
