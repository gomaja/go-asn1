// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	strings "strings"
	testing "testing"
)

// TestVectorGlobalGnbIdRepeatedFieldErrorPath verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.2; malformed GlobalGNB-ID diagnostics retain the containing field and selected GNB-ID alternative.
func TestVectorGlobalGnbIdRepeatedFieldErrorPath(t *testing.T) {
	input := asn1VectorHex(t, "0001020300")
	codec := s11.GlobalGNBIDCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err == nil {
		t.Fatal("known malformed value decoded successfully")
	}
	if !strings.Contains(err.Error(), "per: data truncated") {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(err.Error(), "GNBID.GNBID") {
		t.Fatalf("path: %v", err)
	}
	_ = decoded
}
