// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func apiRefused(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, aper.ErrInvalidValue) {
		t.Errorf("mismatched selector encoded: %v", err)
	}
}
