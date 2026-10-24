// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	testing "testing"
)

// TestVectorAdmittedItemDapsExtensionValue verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.7 and 9.3.8; published E-RAB admitted-item extension object-set dispatch.
func TestVectorAdmittedItemDapsExtensionValue(t *testing.T) {
	input := asn1VectorHex(t, "00")
	if got := s06.ERABsAdmittedItemExtIEs().ID().Source().Assignment; got != "E-RABs-Admitted-Item-ExtIEs" {
		t.Fatalf("table = %s", got)
	}
	codec := s06.ERABsAdmittedItemExtIEs().DAPSResponseInfo().Codec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "DAPSResponseIndicator", "0")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
