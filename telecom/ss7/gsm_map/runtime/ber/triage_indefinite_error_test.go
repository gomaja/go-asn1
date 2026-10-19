// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/triage_indefinite_error_test.go; SHA-256 5d70568bf04fcf7370a38a3c2e2366e907141e2a7055ee3269e3bfa480b83cc7.
package ber

import (
	"errors"
	"testing"
)

// X.690 (02/2021) §8.1.3.6 permits indefinite lengths only for constructors.
// Primitive indefinite lengths are malformed BER, regardless of DER policy.
func TestBERPrimitiveIndefiniteErrorClass(t *testing.T) {
	for _, s := range []string{"03800000", "04800000", "0c800000"} {
		wire := structureWire(t, s)
		if err := ValidateBERElement(wire); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("validator %s: %v", s, err)
		}
		if _, _, _, err := DecodeTLV(wire); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("prefix %s: %v", s, err)
		}
	}
	if _, _, _, err := DecodeBitString(structureWire(t, "03800000")); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("bits: %v", err)
	}
	if _, _, err := DecodeOctetString(structureWire(t, "04800000")); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("octets: %v", err)
	}
	if _, _, err := DecodeString(structureWire(t, "0c800000"), 12); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("string: %v", err)
	}
	if _, _, _, err := DecodeTLV(structureWire(t, "3080058000000000")); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("nested: %v", err)
	}
}
