// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/real_decimal_test.go; SHA-256 d664615870c4b30d3b31c0f6eb89b8e687990ae6c50d9c7585c439b816b6e17b.
package ber

import (
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

func TestValidateDERRejectsNonCanonicalReal(t *testing.T) {
	tests := [][]byte{
		{0x01, '1'},
		{0x02, '1', '.', '0'},
		{0x03, '+', '1', '.', 'E', '+', '0'},
		{0x03, '0', '1', '.', 'E', '+', '0'},
		{0x03, '1', '0', '.', 'E', '+', '0'},
		{0x03, '1', '.', '0', 'E', '+', '0'},
		{0x03, '1', '.', 'E', '0'},
		{0x03, '1', '.', 'E', '+', '1'},
		{0x90, 0x00, 0x01},
		{0x84, 0x00, 0x01},
		{0x81, 0x00, 0x00, 0x01},
		{0x80, 0x00, 0x02},
		{0x80, 0x00, 0x00, 0x01},
	}
	for _, contents := range tests {
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents))
		if err := ValidateDERElement(wire); err == nil {
			t.Errorf("ValidateDERElement(%x) accepted non-canonical REAL", wire)
		}
	}
}
