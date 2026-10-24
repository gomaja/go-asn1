// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	testing "testing"
)

// TestVectorErabSetupPrivateIePreserved verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.3.8; unknown and private ProtocolIE-Field values remain raw.
func TestVectorErabSetupPrivateIePreserved(t *testing.T) {
	input := asn1VectorHex(t, "deadbeef")
	field, err := s11.ERABsToBeSetupItemIEs().NewOpaque(s00.ProtocolIEID(65532), s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	if got := s11.ERABsToBeSetupItemIEs().ID().Source().Assignment; got != "E-RABs-ToBeSetup-ItemIEs" {
		t.Fatalf("table = %s", got)
	}
	asn1VectorAssertPath(t, &field, "Id", "65532")
	asn1VectorAssertPath(t, &field, "Value.Opaque.Bytes", "\"3q2+7w==\"")
}
