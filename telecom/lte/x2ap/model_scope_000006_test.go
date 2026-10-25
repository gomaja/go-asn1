// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s03 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s03"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	testing "testing"
)

// TestContractPc5QosFlowItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.2; PC5 QoS flow item extension owner.
func TestContractPc5QosFlowItemExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s08.PC5QoSFlowItemExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s05.PC5QoSFlowItem
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s03.X2apInternalPC5QoSFlowItemExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "PC5QoSFlowItem-ExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
