// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/profile_root_kind_test.go; SHA-256 47ce2b43ee8f7eecc5cd3e3d5fb74e17f65215533003733d13064e1e9a94496e.
package ber

import (
	"errors"
	"testing"
)

func TestUnknownProfileRootRetainsUnclassifiedOuterType(t *testing.T) {
	// An unknown root supplies no schema for its outer EXTERNAL value.
	// The default root still recognizes EXTERNAL's octet-aligned encoding.
	wire := []byte{0x28, 5, 0xa1, 3, 2, 1, 0}
	for _, root := range []string{"UnknownRoot", "Code", "InvokeId", "TCInvokeIdSet"} {
		if err := ValidateBERElement(wire, TrackTCAPForm(nil, root)...); err != nil {
			t.Fatalf("root %s acquired an outer schema: %v", root, err)
		}
	}
	var violation *ValidationError
	if err := ValidateBERElement(wire, TrackTCAPForm(nil)...); !errors.As(err, &violation) {
		t.Fatalf("default profile lost EXTERNAL segment validation: %v", err)
	}
}
