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

// TestContractAdmittedAddedItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.2; published admitted-to-be-added item extension owner.
func TestContractAdmittedAddedItemExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s06.ERABsToBeAddedSgNBAddReqAckItemExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s10.ERABsAdmittedToBeAddedSgNBAddReqAckItem
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s02.X2apInternalERABsToBeAddedSgNBAddReqAckItemExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "E-RABs-ToBeAdded-SgNBAddReqAck-ItemExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
