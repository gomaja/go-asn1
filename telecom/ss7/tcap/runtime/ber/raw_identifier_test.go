// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/raw_identifier_test.go; SHA-256 3cf140f1c6f9aa2f9862b3cfbafbed6d0f877ca383a42db964f4b6450c80dea5.
package ber

import (
	"bytes"
	"encoding/hex"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

// X.690 (02/2021) §§8.1.2, 8.18.6: retain the inner identifier,
// independently of EXTERNAL's explicit context-specific wrapper.
func TestExternalRawIdentifier(t *testing.T) {
	for _, tc := range []struct {
		name, hex     string
		class, number int
		constructed   bool
	}{
		{"universal", "040101", 0, 4, false},
		{"context", "830101", 2, 3, false},
		{"application high tag", "7f8100020500", 1, 128, true},
		{"private indefinite", "e38005000000", 3, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			choice, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 0, Constructed: true}, inner)
			if err != nil {
				t.Fatal(err)
			}
			content := append([]byte{6, 2, 42, 3}, choice...)
			wire, err := EncodeTLV(tag.Tag{Number: 8, Constructed: true}, content)
			if err != nil {
				t.Fatal(err)
			}
			for _, opts := range [][]DecodeOption{nil, {WithoutReplayCapture()}} {
				value, n, err := DecodeExternal(wire, opts...)
				if err != nil || n != len(wire) {
					t.Fatalf("decode: %d %v", n, err)
				}
				raw := value.SingleASN1Type
				if raw.Class != tc.class || raw.Tag != tc.number || raw.Constructed != tc.constructed || !bytes.Equal(raw.Bytes, inner) {
					t.Fatalf("inner identifier: %+v, want %d/%d/%t", raw, tc.class, tc.number, tc.constructed)
				}
				out, err := EncodeExternal(value)
				if err != nil || !bytes.Equal(out, wire) {
					t.Fatalf("replay %x != %x: %v", out, wire, err)
				}
			}
		})
	}
}
