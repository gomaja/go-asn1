package x2ap

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func asn1ContractHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestContractNeighbourInformationInlineExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; inline Neighbour-Information extension owner.
// Regression: go-asn1-v0.4.2.x2ap.inline-neighbour-extension-owner
func TestContractNeighbourInformationInlineExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value NeighbourInformationElem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "NeighbourInformationElem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "NeighbourInformationElem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "Neighbour-Information-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "Neighbour-Information-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractNrNeighbourInformationInlineExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; inline NRNeighbour-Information extension owner.
// Regression: go-asn1-v0.4.2.x2ap.inline-nr-neighbour-extension-owner
func TestContractNrNeighbourInformationInlineExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value NRNeighbourInformationElem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "NRNeighbourInformationElem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "NRNeighbourInformationElem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "NRNeighbour-Information-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "NRNeighbour-Information-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractRsrpMrListInlineExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; inline RSRPMRList extension owner.
// Regression: go-asn1-v0.4.2.x2ap.inline-rsrp-extension-owner
func TestContractRsrpMrListInlineExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value RSRPMRListElem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "RSRPMRListElem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "RSRPMRListElem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "RSRPMRList-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "RSRPMRList-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractServedCellsInlineExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; inline ServedCells extension owner.
// Regression: go-asn1-v0.4.2.x2ap.inline-served-cell-extension-owner
func TestContractServedCellsInlineExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value ServedCellsElem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "ServedCellsElem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "ServedCellsElem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "ServedCell-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "ServedCell-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractPc5FlowBitRatesExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; PC5 flow bit rates extension owner.
// Regression: go-asn1-v0.5.0.x2ap.pc5-flow-bit-rates-extension-owner
func TestContractPc5FlowBitRatesExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value PC5FlowBitRates
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "PC5FlowBitRates.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "PC5FlowBitRates.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "PC5FlowBitRates-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "PC5FlowBitRates-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractPc5QosFlowItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; PC5 QoS flow item extension owner.
// Regression: go-asn1-v0.5.0.x2ap.pc5-qos-flow-item-extension-owner
func TestContractPc5QosFlowItemExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value PC5QoSFlowItem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "PC5QoSFlowItem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "PC5QoSFlowItem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "PC5QoSFlowItem-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "PC5QoSFlowItem-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractPc5QosParametersExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; PC5 QoS parameters extension owner.
// Regression: go-asn1-v0.5.0.x2ap.pc5-qos-parameters-extension-owner
func TestContractPc5QosParametersExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value PC5QoSParameters
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "PC5QoSParameters.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "PC5QoSParameters.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "PC5QoSParameters-ExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "PC5QoSParameters-ExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractAdmittedAddedItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; published admitted-to-be-added item extension owner.
// Regression: go-asn1-v0.4.2.x2ap.admitted-added-extension-owner
func TestContractAdmittedAddedItemExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value ERABsAdmittedToBeAddedSgNBAddReqAckItem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "ERABsAdmittedToBeAddedSgNBAddReqAckItem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "ERABsAdmittedToBeAddedSgNBAddReqAckItem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "E-RABs-ToBeAdded-SgNBAddReqAck-ItemExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "E-RABs-ToBeAdded-SgNBAddReqAck-ItemExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractAdmittedModifiedItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; published admitted-to-be-modified item extension owner.
// Regression: go-asn1-v0.4.2.x2ap.admitted-modified-extension-owner
func TestContractAdmittedModifiedItemExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value ERABsAdmittedToBeModifiedSgNBModAckItem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "ERABsAdmittedToBeModifiedSgNBModAckItem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "ERABsAdmittedToBeModifiedSgNBModAckItem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "E-RABs-ToBeAdded-SgNBModAck-ItemExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "E-RABs-ToBeAdded-SgNBModAck-ItemExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}

// TestContractAdmittedReleasedItemExtensionOwner verifies 3GPP TS 36.423 V19.1.0 (2026-02), section 9.2; published admitted-to-be-released item extension owner.
// Regression: go-asn1-v0.4.2.x2ap.admitted-released-extension-owner
func TestContractAdmittedReleasedItemExtensionOwner(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "deadbeef")
	field := ProtocolExtensionField{Id: 65532}
	field.ExtensionValue.Bytes = input
	var value ERABsAdmittedToReleasedSgNBModAckItem
	value.IEExtensions = ProtocolExtensionContainer{field}
	decoded, err := DecodeProtocolExtensionsRecursive(&value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded extensions = %d, want 1", len(decoded))
	}
	if decoded[0].Path != "ERABsAdmittedToReleasedSgNBModAckItem.IEExtensions[0]" {
		t.Fatalf("path = %q, want %q", decoded[0].Path, "ERABsAdmittedToReleasedSgNBModAckItem.IEExtensions[0]")
	}
	if decoded[0].ObjectSet != "E-RABs-ToBeReleased-SgNBModAck-ItemExtIEs" {
		t.Fatalf("object set = %q, want %q", decoded[0].ObjectSet, "E-RABs-ToBeReleased-SgNBModAck-ItemExtIEs")
	}
	if decoded[0].Value != nil {
		t.Fatalf("unknown extension value = %T, want nil", decoded[0].Value)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, input) {
		t.Fatalf("raw extension = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, input)
	}
}
