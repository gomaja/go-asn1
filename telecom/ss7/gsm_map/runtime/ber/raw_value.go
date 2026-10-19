// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/raw_value.go; SHA-256 4f2a12af32ec708fd70bd550e1bd470ffe37543435c9f697aa04a78adcbc000d.
package ber

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// ValidateRawValueIdentifier checks the identifier metadata accompanying the
// complete opaque bytes. Bytes remain the sole encoding input; an inconsistent
// descriptor is never silently repaired. X.690 (02/2021) §§8.1.2.1, 8.1.2.5.
// The caller must also validate the complete BER or DER element.
func ValidateRawValueIdentifier(value runtime.RawValue) error {
	identifier, _, err := DecodeTag(value.Bytes)
	if err != nil {
		return fmt.Errorf("%w: RawValue identifier: %w", ErrInvalidValue, err)
	}
	if value.Class != int(identifier.Class) || value.Tag != identifier.Number || value.Constructed != identifier.Constructed {
		return fmt.Errorf("%w: RawValue metadata does not match its encoded identifier", ErrInvalidValue)
	}
	return nil
}
