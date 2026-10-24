// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	testing "testing"
)

// TestContractNrNeighbourInformationInlineExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; inline NRNeighbour-Information extension owner.
func TestContractNrNeighbourInformationInlineExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s14.NRNeighbourInformationExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s16.NRNeighbourInformationElem
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s14.X2apInternalNRNeighbourInformationExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "NRNeighbour-Information-ExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
