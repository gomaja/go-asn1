// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/oid_checked_test.go; SHA-256 c2229c6d357d9a9369813f3dd9e1f1b1fc6ec7fbb5b10b250cb77e57f88c4bc1.
package ber

import (
	"errors"
	"testing"
)

func TestOIDDecoderClassifiesLoneContinuationAsTruncated(t *testing.T) {
	if _, err := DecodeOIDValue([]byte{0x2a, 0x80}); !errors.Is(err, ErrTruncated) {
		t.Fatal(err)
	}
}
