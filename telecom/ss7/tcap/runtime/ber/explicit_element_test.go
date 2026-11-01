// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/explicit_element_test.go; SHA-256 96fecc8f46c93078e5f5853c255bf410d66c2f6cdbb13807d2db8f1fe685c1a3.
package ber

import (
	"errors"
	"testing"
)

func assertElementSentinels(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("error=%v, want %v", got, want)
	}
	for _, sentinel := range []error{ErrUnexpectedElement, ErrTruncated, ErrInvalidTag, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit} {
		if errors.Is(got, sentinel) != (want == sentinel) {
			t.Errorf("%v: errors.Is(%v)=%t, want %t", got, sentinel, errors.Is(got, sentinel), want == sentinel)
		}
	}
}
