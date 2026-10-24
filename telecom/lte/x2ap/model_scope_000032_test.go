// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	testing "testing"
)

// TestVectorAdmittedItemUnknownExtensionField verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.2.4 and 9.3.8; unknown ProtocolExtensionField values remain raw.
func TestVectorAdmittedItemUnknownExtensionField(t *testing.T) {
	input := asn1VectorHex(t, "deadbeef")
	field, err := s06.ERABsAdmittedItemExtIEs().NewOpaque(s00.ProtocolIEID(65532), s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	if got := s06.ERABsAdmittedItemExtIEs().ID().Source().Assignment; got != "E-RABs-Admitted-Item-ExtIEs" {
		t.Fatalf("table = %s", got)
	}
	asn1VectorAssertPath(t, &field, "Id", "65532")
	asn1VectorAssertPath(t, &field, "ExtensionValue.Opaque.Bytes", "\"3q2+7w==\"")
}
