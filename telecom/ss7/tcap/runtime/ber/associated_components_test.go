// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/associated_components_test.go; SHA-256 62dd29e5b40b839f721b926e565c06566aa1871adef9940e9d104c1fec238bfb.
package ber

import (
	"encoding/hex"
	"testing"
)

// X.690 §§8.9.2, 8.17.1, 8.18.1, 8.24.1: ordering and completeness
// are schema rules; an incomplete or malformed tail retains its BER error.
func TestAssociatedComponentsOrderAndMalformedTail(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, row := range []struct {
			body []byte
			want error
		}{
			{nil, ErrUnexpectedElement}, {[]byte{0x82, 0, 0xa0, 2, 0x85, 0}, ErrUnexpectedElement},
			{[]byte{0xa0, 2, 0x85, 0, 0x81, 0, 0x82, 0}, ErrUnexpectedElement},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 5}, ErrTruncated},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 0, 0}, ErrInvalidTag},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 0x22, 0}, ErrInvalidTag},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 5, 1}, ErrTruncated},
		} {
			wire := associatedCardinalityTLV(outer, row.body, false)
			checkAssociatedCardinalityError(t, ValidateBERElement(wire), row.want)
		}
	}
	for _, row := range []struct {
		body []byte
		want error
	}{
		{[]byte{6, 1, 0x2a}, ErrUnexpectedElement},
		{[]byte{6, 1, 0x2a, 0x83, 0}, ErrUnexpectedElement},
		{[]byte{6, 1, 0x2a, 0xa0, 2, 5, 0, 5, 0}, ErrUnexpectedElement},
		{[]byte{6, 1, 0x2a, 0x82, 0}, ErrInvalidValue},
		{[]byte{6, 1, 0x2a, 0x82, 1, 8}, ErrInvalidValue},
		{[]byte{6, 1, 0x2a, 0xa0, 2, 5, 0, 5}, ErrTruncated},
	} {
		wire := associatedCardinalityTLV(0x28, row.body, false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire), row.want)
	}
}

// The same universal rules apply in a foreign TC-user argument (§8.15).
func TestAssociatedComponentsTCUserArgument(t *testing.T) {
	for _, row := range []struct {
		value string
		want  error
	}{
		{"2804a0020500", ErrInvalidValue}, {"2b0ba00581032a030481008200", ErrUnexpectedElement},
		{"3d0ba00581032a030481008200", ErrUnexpectedElement}, {"3d08a004820200018200", ErrInvalidValue},
		{"3d07a0028500820141", nil},
	} {
		value, err := hex.DecodeString(row.value)
		if err != nil {
			t.Fatal(err)
		}
		invoke := associatedCardinalityTLV(0xa1, append([]byte{2, 1, 1, 2, 1, 0x2d}, value...), false)
		wire := associatedCardinalityTLV(0x62, append([]byte{0x48, 1, 1}, associatedCardinalityTLV(0x6c, invoke, false)...), false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...), row.want)
	}
}

// X.690 (02/2021) §8.14.3: an extra identification value is outside
// the abstract syntax; its context-specific contents have no inferred type.
func TestAssociatedComponentsExtraAlternativeKeepsUnknownContents(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, second := range [][]byte{{0x80, 0}, {0x81, 1, 0x80}, {0x82, 2, 0, 1}, {0x83, 0}, {0x84, 1, 0x80}, {0xa5, 0}, {0x85, 1, 0}} {
			checkAssociatedCardinalityError(t, ValidateBERElement(second), nil)
			wrapper := associatedCardinalityTLV(0xa0, append([]byte{0x85, 0}, second...), false)
			wire := associatedCardinalityTLV(outer, append(wrapper, 0x82, 0), false)
			checkAssociatedCardinalityError(t, ValidateBERElement(wire), ErrUnexpectedElement)
		}
		// A universal INTEGER still identifies its own base type in an extra
		// value and retains the same contents failure as a standalone INTEGER.
		second := []byte{2, 2, 0, 1}
		checkAssociatedCardinalityError(t, ValidateBERElement(second), ErrInvalidValue)
		wrapper := associatedCardinalityTLV(0xa0, append([]byte{0x85, 0}, second...), false)
		wire := associatedCardinalityTLV(outer, append(wrapper, 0x82, 0), false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire), ErrInvalidValue)
	}
}

// X.690 (02/2021) §§8.15, 8.17.1, 8.18.4, 8.24.1: an unadmitted
// root or a misplaced universal value inside an admitted message has no
// profile-owned EXTERNAL position that could defer validation.
func TestAssociatedComponentsGeneratedProfilePositions(t *testing.T) {
	for _, row := range []struct {
		wire string
		want error
	}{
		{"2800", ErrInvalidValue}, {"2804a0020500", ErrInvalidValue},
		{"2b08a004820200018200", ErrInvalidValue}, {"3d0ba00581032a030481008200", ErrUnexpectedElement},
		{"62094801012804a0020500", ErrInvalidValue},
		{"620d4801012b08a004820200018200", ErrInvalidValue},
		{"62104801013d0ba00581032a030481008200", ErrUnexpectedElement},
	} {
		wire, err := hex.DecodeString(row.wire)
		if err != nil {
			t.Fatal(err)
		}
		opts := TrackTCAPForm(nil, "TCMessage")
		config, err := decodeOptions(opts)
		if err != nil {
			t.Fatal(err)
		}
		config.generatedPreflight = true
		checkAssociatedCardinalityError(t, validateBERElement(wire, opts, config), row.want)
	}
}
