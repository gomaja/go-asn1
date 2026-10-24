// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	strings "strings"
	testing "testing"
)

// TestVectorX2apPduHeader verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1 and 9.2.3; X2AP-PDU initiating-message APER header.
func TestVectorX2apPduHeader(t *testing.T) {
	input := asn1VectorHex(t, "002e0002bbcc")
	codec := s19.X2APPDUCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err == nil {
		t.Fatal("known malformed value decoded successfully")
	}
	if !strings.Contains(err.Error(), "non-zero APER alignment padding") {
		t.Fatalf("decode: %v", err)
	}
	_ = decoded
}
