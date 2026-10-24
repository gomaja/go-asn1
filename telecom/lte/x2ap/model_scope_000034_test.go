// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	strings "strings"
	testing "testing"
)

// TestVectorAdmittedItemMalformedDapsPath verifies ITU-T X.691 (02/2021), clauses 11.1.3.1, 11.1.4, and 11.2; 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.3.4, 9.3.7, and 9.3.8; zero-length DAPS open types are rejected with the complete containing path and identifier.
func TestVectorAdmittedItemMalformedDapsPath(t *testing.T) {
	input := asn1VectorHex(t, "12800000016e0000")
	codec := s09.ERABsAdmittedItemCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err == nil {
		t.Fatal("known malformed value decoded successfully")
	}
	if !strings.Contains(err.Error(), "APER open type has an empty complete encoding") {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(err.Error(), "IEExtensions[0].ExtensionValue") {
		t.Fatalf("path: %v", err)
	}
	_ = decoded
}
