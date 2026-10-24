// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	strings "strings"
	testing "testing"
)

// TestVectorErabSetupMalformedIePath verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2.4; malformed nested open-type diagnostics retain the full field path.
func TestVectorErabSetupMalformedIePath(t *testing.T) {
	input := asn1VectorHex(t, "00")
	if got := s11.ERABsToBeSetupItemIEs().ID().Source().Assignment; got != "E-RABs-ToBeSetup-ItemIEs" {
		t.Fatalf("table = %s", got)
	}
	codec := s11.ERABsToBeSetupItemIEs().ERABsToBeSetupItem().Codec()
	decoded, _, err := codec.DecodeAPER(input)
	if err == nil {
		t.Fatal("known malformed value decoded successfully")
	}
	if !strings.Contains(err.Error(), "per: data truncated") {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(err.Error(), "ERABsToBeSetupItem") {
		t.Fatalf("path: %v", err)
	}
	_ = decoded
}
