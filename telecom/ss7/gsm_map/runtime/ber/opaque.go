// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque.go; SHA-256 553a080825777defd29e2559f93eb1f0d80fbc5e64b4bfde6ff4e01c7ef53461.
package ber

import "fmt"

// CheckBEROpaqueElement applies the canonical-opaque override used by generated
// TCAP encoders to MAP's open values and unknown additions. X.690 (02/2021)
// §§8.13, 8.15, 10, 11: one complete element that already passes the DER checks
// can be copied in a fresh encoding. Unknown IMPLICIT types, foreign DEFAULTs
// and schema-dependent SET ordering cannot be certified without their schema.
// A value requiring repair must instead be supplied through its typed codec.
func CheckBEROpaqueElement(data []byte, options ...EncodeOption) error {
	if err := ValidateEncodeOptions(options...); err != nil {
		return err
	}
	if err := CheckBEROpaqueReplay(options...); err == nil {
		return nil
	}
	if err := ValidateDEREncodedElement(data); err != nil {
		return fmt.Errorf("%w: opaque element requires a typed value for canonical repair: %w", ErrInvalidValue, err)
	}
	return nil
}
