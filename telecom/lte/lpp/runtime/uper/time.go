// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/time.go; SHA-256 a07b54f7bf29877dd2124908cda8051acf5d1be1ac853c7f816a2799e4bd15e7.
package uper

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/lte/lpp/runtime"
)

// X.691 (02/2021) §10.6.5 encodes UTCTime as its VisibleString definition in
// X.680 (02/2021) §47.3, restricted as X.690 (02/2021) §11.8 requires in
// both BASIC-PER and CANONICAL-PER. EncodeUTCTime therefore emits
// Canonical(); a value with no canonical form, or an unset value, is
// rejected with ErrInvalidValue wrapping the runtime error.
func EncodeUTCTime(bb *BitBuffer, value runtime.UTCTime) error {
	text, err := canonicalUTCTime(value)
	if err != nil {
		return err
	}
	return EncodeKnownMultiplierString(bb, text, 7, 0, 0, false)
}

// DecodeUTCTime accepts only the X.690 (02/2021) §11.8 form that
// X.691 (02/2021) §10.6.5 requires.
func DecodeUTCTime(bb *BitBuffer) (runtime.UTCTime, error) {
	text, err := DecodeKnownMultiplierString(bb, 7, 0, 0, false)
	if err != nil {
		return runtime.UTCTime{}, err
	}
	return parseCanonicalUTCTime(text)
}

// In aligned PER, each character of this VisibleString takes B2 = 8 bits
// (X.691 (02/2021) 30.5.2), as checked against pycrate 0.7.11.

// DecodeUTCTimeAligned accepts only the X.690 (02/2021) §11.8 form.

// UTCTimeEquals reports whether value is encoded as the canonical text, the
// X.690 (02/2021) §11.8 form that X.691 (02/2021) §10.6.5 transmits. A value
// that has no such form equals nothing.
func UTCTimeEquals(value runtime.UTCTime, canonical string) bool {
	text, err := canonicalUTCTime(value)
	return err == nil && text == canonical
}

func canonicalUTCTime(value runtime.UTCTime) (string, error) {
	canonical, err := value.Canonical()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	return canonical.String(), nil
}

func parseCanonicalUTCTime(text string) (runtime.UTCTime, error) {
	value, err := runtime.ParseUTCTime(text)
	if err != nil {
		return runtime.UTCTime{}, fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	if !value.IsCanonical() {
		return runtime.UTCTime{}, fmt.Errorf("%w: noncanonical UTCTime %q (X.691 (02/2021) §10.6.5, X.690 (02/2021) §11.8)", ErrInvalidValue, text)
	}
	return value, nil
}
