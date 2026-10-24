// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	testing "testing"
)

// TestVectorErabSetupItemRecursiveIe verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.1.1 and 9.2.1; nested E-RAB open types retain their ASN.1 object-set context.
func TestVectorErabSetupItemRecursiveIe(t *testing.T) {
	input := asn1VectorHex(t, "4500060701f00afd0055037806f5")
	if got := s11.ERABsToBeSetupItemIEs().ID().Source().Assignment; got != "E-RABs-ToBeSetup-ItemIEs" {
		t.Fatalf("table = %s", got)
	}
	codec := s11.ERABsToBeSetupItemIEs().ERABsToBeSetupItem().Codec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "ERABID", "5")
	asn1VectorAssertPath(t, &decoded.Value, "ERABLevelQoSParameters.QCI", "6")
	asn1VectorAssertPath(t, &decoded.Value, "ERABLevelQoSParameters.AllocationAndRetentionPriority.PriorityLevel", "1")
	asn1VectorAssertPath(t, &decoded.Value, "DLForwarding", "0")
	asn1VectorAssertPath(t, &decoded.Value, "ULGTPtunnelEndpoint.TransportLayerAddress.BitLength", "32")
	asn1VectorAssertPath(t, &decoded.Value, "ULGTPtunnelEndpoint.GTPTEID", "\"A3gG9Q==\"")
}
