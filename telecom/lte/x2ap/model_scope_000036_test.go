// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	strings "strings"
	testing "testing"
)

// TestVectorErabSetupMalformedDapsFullPath verifies 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.3.4, 9.3.5, and 9.3.7; malformed DAPS extension diagnostics retain the complete containing path.
func TestVectorErabSetupMalformedDapsFullPath(t *testing.T) {
	input := asn1VectorHex(t, "2500093c03e00a000001deadbeef0000016b4001ff")
	codec := s11.ERABsToBeSetupItemCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err == nil {
		t.Fatal("known malformed value decoded successfully")
	}
	if !strings.Contains(err.Error(), "non-zero APER alignment padding") {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(err.Error(), "IEExtensions[0].ExtensionValue") {
		t.Fatalf("path: %v", err)
	}
	_ = decoded
}
