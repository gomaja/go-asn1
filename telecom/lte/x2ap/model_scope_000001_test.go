// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	testing "testing"
)

// TestContractNeighbourInformationInlineExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.2; inline Neighbour-Information extension owner.
func TestContractNeighbourInformationInlineExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s08.NeighbourInformationExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s09.NeighbourInformationElem
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s08.X2apInternalNeighbourInformationExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "Neighbour-Information-ExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
