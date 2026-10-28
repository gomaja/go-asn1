// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/external_element_test.go; SHA-256 2a5d009bd9777adf8fb9230551f070eace169cdeff612692c3039829f5bfb7c8.
package ber

import (
	"errors"
	"testing"
)

// X.690 (02/2021) §§8.1.2, 8.18.1 require a complete encoding for
// each EXTERNAL component and exactly one encoding choice.
func TestExternalValueExtraElementClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{"complete extra", []byte{0x06, 0x01, 0x2a, 0xa0, 0x02, 0x05, 0x00, 0x05, 0x00}, ErrUnexpectedElement},
		{"incomplete extra", []byte{0x06, 0x01, 0x2a, 0xa0, 0x02, 0x05, 0x00, 0x05}, ErrTruncated},
		{"invalid extra tag", []byte{0x06, 0x01, 0x2a, 0xa0, 0x02, 0x05, 0x00, 0x1f, 0x80, 0x00}, ErrInvalidTag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeExternalValue(tc.wire)
			if !errors.Is(err, tc.want) || errors.Is(err, ErrUnexpectedElement) != (tc.want == ErrUnexpectedElement) {
				t.Fatalf("error = %v, want only %v", err, tc.want)
			}
		})
	}
}
