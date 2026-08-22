package x2ap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

func TestDecodeProtocolIEsRecursiveERABsToBeSetupItem(t *testing.T) {
	// 3GPP TS 36.423 V19.1.0, X2AP-PDU-Contents:
	// E-RABs-ToBeSetup-List applies E-RABs-ToBeSetup-ItemIEs to each container.
	raw, err := hex.DecodeString("4500060701f00afd0055037806f5")
	if err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	value := &UEContextInformation{
		ERABsToBeSetupList: ERABsToBeSetupList{{
			Id: IdERABsToBeSetupItem, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: raw},
		}},
	}

	decoded, err := DecodeProtocolIEsRecursive(value)
	if err != nil {
		t.Fatalf("recursive decode: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded fields = %d, want 1", len(decoded))
	}
	node := decoded[0]
	if node.Path != "UEContextInformation.ERABsToBeSetupList[0]" {
		t.Errorf("decoded path = %q", node.Path)
	}
	if node.ObjectSet != "E-RABs-ToBeSetup-ItemIEs" {
		t.Errorf("decoded object set = %q", node.ObjectSet)
	}
	if !bytes.Equal(node.Field.Value.Bytes, raw) {
		t.Errorf("retained raw value = %x, want %x", node.Field.Value.Bytes, raw)
	}

	item, ok := node.Value.(*ERABsToBeSetupItem)
	if !ok {
		t.Fatalf("decoded value type = %T, want *ERABsToBeSetupItem", node.Value)
	}
	if item.ERABID != 5 {
		t.Errorf("E-RAB ID = %d, want 5", item.ERABID)
	}
	if item.ERABLevelQoSParameters.QCI != 6 {
		t.Errorf("QCI = %d, want 6", item.ERABLevelQoSParameters.QCI)
	}
	priority := item.ERABLevelQoSParameters.AllocationAndRetentionPriority
	if priority.PriorityLevel != 1 || priority.PreEmptionCapability != 1 || priority.PreEmptionVulnerability != 1 {
		t.Errorf("allocation priority = %#v, want level/capability/vulnerability 1", priority)
	}
	if item.DLForwarding == nil || *item.DLForwarding != DLForwardingDLForwardingProposed {
		t.Errorf("DL forwarding = %v, want proposed", item.DLForwarding)
	}
	if got := item.ULGTPtunnelEndpoint.TransportLayerAddress; got.BitLength != 32 || !bytes.Equal(got.Bytes, []byte{10, 253, 0, 85}) {
		t.Errorf("transport address = (%d, %x), want (32, 0afd0055)", got.BitLength, got.Bytes)
	}
	if got := item.ULGTPtunnelEndpoint.GTPTEID; !bytes.Equal(got, []byte{0x03, 0x78, 0x06, 0xf5}) {
		t.Errorf("GTP TEID = %x, want 037806f5", got)
	}
}

func TestDecodeProtocolIEsRecursiveAccessAndMobilityNRRAReport(t *testing.T) {
	// 3GPP TS 38.331 V19.3.0 section 6.3.2, RA-ReportList-r16: one report
	// for PCI/ARFCN 0, access-related purpose, and no optional RA information.
	// TShark 4.6.8 independently decodes it without a malformed marker.
	nrRRCReport := []byte{0x04, 0, 0, 0, 0, 0}
	list := per.NewBitBuffer()
	if err := per.EncodeConstrainedWholeNumberAligned(list, 1, 1, 64); err != nil {
		t.Fatalf("encoding NRRAReport length: %v", err)
	}
	if err := (&NRRAReportListItem{NRRAReport: NRRAReportContainer(nrRRCReport)}).MarshalAPERTo(list); err != nil {
		t.Fatalf("encoding NRRAReport item: %v", err)
	}

	value := &AccessAndMobilityIndication{ProtocolIEs: ProtocolIEContainer{{
		Id: IdNRRAReport, Criticality: CriticalityIgnore,
		Value: runtime.RawValue{Bytes: list.Bytes()},
	}}}
	decoded, err := DecodeProtocolIEsRecursive(value)
	if err != nil {
		t.Fatalf("recursive AccessAndMobilityIndication decode: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded fields = %d, want 1", len(decoded))
	}
	if decoded[0].ObjectSet != "AccessAndMobilityIndication-IEs" {
		t.Errorf("object set = %q, want AccessAndMobilityIndication-IEs", decoded[0].ObjectSet)
	}
	report, ok := decoded[0].Value.(*NRRAReport)
	if !ok {
		t.Fatalf("decoded value type = %T, want *NRRAReport", decoded[0].Value)
	}
	if len(*report) != 1 || !bytes.Equal((*report)[0].NRRAReport, nrRRCReport) {
		t.Errorf("decoded NRRAReport = %#v", *report)
	}
}

func TestDecodeProtocolIEFieldsRecursivePreservesUnknownPrivateIE(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	decoded, err := DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{{
		Id: 65532, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: raw},
	}})
	if err != nil {
		t.Fatalf("decoding unknown private IE: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Value != nil {
		t.Fatalf("unknown private IE result = %#v, want one unresolved node", decoded)
	}
	if !bytes.Equal(decoded[0].Field.Value.Bytes, raw) {
		t.Errorf("unknown private IE raw value = %x, want %x", decoded[0].Field.Value.Bytes, raw)
	}
}

func TestDecodeProtocolIEsRecursiveReportsNestedPath(t *testing.T) {
	value := &UEContextInformation{ERABsToBeSetupList: ERABsToBeSetupList{{Id: IdERABsToBeSetupItem}}}
	_, err := DecodeProtocolIEsRecursive(value)
	if err == nil || !strings.Contains(err.Error(), "UEContextInformation.ERABsToBeSetupList[0]") {
		t.Fatalf("malformed nested IE error = %v, want nested path", err)
	}
}

func FuzzDecodeProtocolIEFieldsRecursive(f *testing.F) {
	f.Add([]byte{0x45, 0x00, 0x06, 0x07, 0x01, 0xf0, 0x0a, 0xfd, 0x00, 0x55, 0x03, 0x78, 0x06, 0xf5})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeProtocolIEFieldsRecursive("E-RABs-ToBeSetup-ItemIEs", []ProtocolIEField{{
			Id: IdERABsToBeSetupItem, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: raw},
		}})
	})
}
