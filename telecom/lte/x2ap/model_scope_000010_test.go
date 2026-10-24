// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	testing "testing"
)

// TestContractAdmittedReleasedItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.2; published admitted-to-be-released item extension owner.
func TestContractAdmittedReleasedItemExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s06.ERABsToBeReleasedSgNBModAckItemExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s05.ERABsAdmittedToReleasedSgNBModAckItem
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s02.X2apInternalERABsToBeReleasedSgNBModAckItemExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "E-RABs-ToBeReleased-SgNBModAck-ItemExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
