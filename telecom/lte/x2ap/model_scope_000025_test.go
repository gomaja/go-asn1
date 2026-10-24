// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	testing "testing"
)

// TestVectorHandoverRequestOldEnbUeId verifies 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.1.1.1 and 9.2.24; HandoverRequest id-Old-eNB-UE-X2AP-ID.
func TestVectorHandoverRequestOldEnbUeId(t *testing.T) {
	input := asn1VectorHex(t, "0007")
	if got := s18.HandoverRequestIEs().ID().Source().Assignment; got != "HandoverRequest-IEs" {
		t.Fatalf("table = %s", got)
	}
	codec := s18.HandoverRequestIEs().OldENBUEX2APID().Codec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "$", "7")
}
