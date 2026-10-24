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

// TestContractPc5FlowBitRatesExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; PC5 flow bit rates extension owner.
func TestContractPc5FlowBitRatesExtensionOwner(t *testing.T) {
	input := asn1ContractHex(t, "deadbeef")
	field, err := s08.PC5FlowBitRatesExtIEs().NewOpaque(65532, s00.CriticalityIgnore, input)
	if err != nil {
		t.Fatal(err)
	}
	var value s05.PC5FlowBitRates
	value.IEExtensions = append(value.IEExtensions, field)
	if got := s03.X2apInternalPC5FlowBitRatesExtIEsValueRule(value.IEExtensions[0].ExtensionValue).Assignment.Assignment; got != "PC5FlowBitRates-ExtIEs" {
		t.Fatalf("table = %s", got)
	}
	opaque, ok := value.IEExtensions[0].ExtensionValue.Opaque()
	if !ok || !bytes.Equal(opaque.Bytes(), input) {
		t.Fatal("opaque extension lost")
	}
}
