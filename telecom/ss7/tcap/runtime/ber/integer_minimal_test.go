// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/integer_minimal_test.go; SHA-256 4d0eab8382ba86e5cc2fbc4c4302070a9a940fbd88eee2c699694905736e3e86.
package ber

import (
	"errors"
	"testing"
)

func TestRejectConstructedNull(t *testing.T) {
	if _, err := DecodeNull([]byte{0x25, 0x00}); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("constructed NULL: %v", err)
	}
}
