// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_root_framing_test.go; SHA-256 06cc139e587127d8da3281b727c61c0c6440974cf7348d6aef81902df272a780.
package ber

import (
	"encoding/hex"
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

// X.690 (02/2021) §§8.1.2, 8.1.3, 8.1.5: retain framing
// diagnostics through the character-string entry point of the owned runtime.
func TestCharacterStringRootFraming(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want error
	}{
		{"02", ErrTruncated},
		{"0201", ErrTruncated},
		{"020100", ErrUnexpectedElement},
		{"0282ff", ErrTruncated},
		{"02ff", ErrInvalidLength},
		{"02800000", ErrInvalidLength},
		{"3080", ErrTruncated},
		{"308000", ErrTruncated},
		{"30800000", ErrUnexpectedElement},
		{"308030800000", ErrTruncated},
		{"3080308000000000", ErrUnexpectedElement},
		{"1f8000", ErrInvalidTag},
		{"0000", ErrInvalidTag},
		// A malformed child identifier keeps its tag error (§8.23.3).
		{"2c0102", ErrInvalidTag},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			_, _, got := DecodeString(wire, tag.TagUTF8String)
			for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit} {
				if errors.Is(got, sentinel) != (sentinel == tc.want) {
					t.Errorf("error = %v, errors.Is(%v), want only %v", got, sentinel, tc.want)
				}
			}
		})
	}
}
