// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	testing "testing"
)

// TestContractAdmittedModifiedItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; published admitted-to-be-modified item extension owner.
func TestContractAdmittedModifiedItemExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s06.ERABsToBeAddedSgNBModAckItemExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s10.ERABsAdmittedToBeModifiedSgNBModAckItem
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s02.X2apInternalERABsToBeAddedSgNBModAckItemExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "E-RABs-ToBeAdded-SgNBModAck-ItemExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
