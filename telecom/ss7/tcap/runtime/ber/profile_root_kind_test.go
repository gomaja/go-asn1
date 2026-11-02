// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/profile_root_kind_test.go; SHA-256 92d9821065af6497636f4e595f618b9bee17dc6a85aed271511a2cdadb6ceaf5.
package ber

import (
	"errors"
	"testing"
)

func TestUnknownProfileRootRetainsUniversalExternalRules(t *testing.T) {
	// X.690 (02/2021) §§8.18.1, 8.7.3: universal EXTERNAL retains its
	// implicit OCTET STRING segment rule even without a profile root schema.
	wire := []byte{0x28, 5, 0xa1, 3, 2, 1, 0}
	for _, root := range []string{"UnknownRoot", "Code", "InvokeId", "TCInvokeIdSet"} {
		if err := ValidateBERElement(wire, TrackTCAPForm(nil, root)...); !errors.Is(err, ErrInvalidTag) {
			t.Fatalf("root %s lost EXTERNAL segment validation: %v", root, err)
		}
	}
	// The default TCMessage root does not admit universal EXTERNAL. Its
	// contents still receive the ordinary X.690 validation.
	if err := ValidateBERElement(wire, TrackTCAPForm(nil)...); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("default profile lost EXTERNAL segment validation: %v", err)
	}
}
