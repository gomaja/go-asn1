// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/explicit_element_test.go; SHA-256 9f234fcf63a113d0d29809a6546e22ba685a97816912457691c422c3439a6220.
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
