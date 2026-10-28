// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/explicit_element_test.go; SHA-256 a01f70e05b883e25afba8f53f2d00e4b60e961fa39398677bd1de50d2ac42ee3.
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
