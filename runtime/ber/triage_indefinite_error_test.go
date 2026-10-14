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
