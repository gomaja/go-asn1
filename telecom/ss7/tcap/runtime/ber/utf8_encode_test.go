// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/utf8_encode_test.go; SHA-256 8374d84866d4ef9b4d7f7f06339724389780f9d4d0bd2f402b8705846ebd2779.
package ber

import (
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

// Builds deliberately malformed received wire without using the validated encoder.
func encodeUTF8WireForTest(t *testing.T, value string) []byte {
	t.Helper()
	return mustEncode(t)(EncodeTLV(tag.Tag{Number: tag.TagUTF8String}, []byte(value)))
}
