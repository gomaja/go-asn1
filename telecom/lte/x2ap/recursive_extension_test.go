package x2ap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

func encodeX2UEID(t *testing.T, value int64) []byte {
	t.Helper()
	bb := per.NewBitBuffer()
	if err := per.EncodeIntegerAligned(bb, value, int64Ptr(0), int64Ptr(4095), false); err != nil {
		t.Fatalf("encoding UE-X2AP-ID: %v", err)
	}
	return bb.Bytes()
}

func encodeX2Octets(t *testing.T, value []byte) []byte {
	t.Helper()
	bb := per.NewBitBuffer()
	if err := per.EncodeOctetStringAligned(bb, value, 0, 0, false); err != nil {
		t.Fatalf("encoding octet string: %v", err)
	}
	return bb.Bytes()
}

func erabsAdmittedListWithDAPS(t *testing.T, erabID ERABID, indicator int64) ([]byte, []byte) {
	t.Helper()
	dapsWire, err := (&DAPSResponseInfo{DAPSResponseIndicator: indicator}).MarshalAPER()
	if err != nil {
		t.Fatalf("encoding DAPS response info: %v", err)
	}
	itemWire, err := (&ERABsAdmittedItem{
		ERABID: erabID,
		IEExtensions: ProtocolExtensionContainer{{
			Id: IdDAPSResponseInfo, Criticality: CriticalityReject,
			ExtensionValue: runtime.RawValue{Bytes: dapsWire},
		}},
	}).MarshalAPER()
	if err != nil {
		t.Fatalf("encoding admitted E-RAB item: %v", err)
	}

	list := per.NewBitBuffer()
	if err := per.EncodeConstrainedWholeNumberAligned(list, 1, 1, MaxnoofBearers); err != nil {
		t.Fatalf("encoding admitted E-RAB list length: %v", err)
	}
	if err := (&ProtocolIEField{
		Id: IdERABsAdmittedItem, Criticality: CriticalityIgnore,
		Value: runtime.RawValue{Bytes: itemWire},
	}).MarshalAPERTo(list); err != nil {
		t.Fatalf("encoding admitted E-RAB list item: %v", err)
	}
	return list.Bytes(), dapsWire
}

func TestSuccessfulOutcomeDecodeValueRecursiveDAPSResponseInfo(t *testing.T) {
	// 3GPP TS 36.423 V19.1.0, X2AP-PDU-Contents: E-RABs-Admitted-Item
	// binds its extension container to E-RABs-Admitted-Item-ExtIEs, where
	// ID 366 maps to DAPSResponseInfo.
	admittedList, dapsWire := erabsAdmittedListWithDAPS(t, 5, 0)
	ack := &HandoverRequestAcknowledge{ProtocolIEs: ProtocolIEContainer{
		{Id: IdOldENBUEX2APID, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: encodeX2UEID(t, 7)}},
		{Id: IdNewENBUEX2APID, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: encodeX2UEID(t, 8)}},
		{Id: IdERABsAdmittedList, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: admittedList}},
		{Id: IdTargeteNBtoSourceENBTransparentContainer, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: encodeX2Octets(t, []byte{0xaa})}},
	}}
	ackWire, err := ack.MarshalAPER()
	if err != nil {
		t.Fatalf("encoding Handover Request Acknowledge: %v", err)
	}
	procedure, err := (&SuccessfulOutcome{
		ProcedureCode: IdHandoverPreparation,
		Criticality:   int64(CriticalityReject),
		Value:         runtime.RawValue{Bytes: ackWire},
	}).DecodeValueRecursive()
	if err != nil {
		t.Fatalf("recursive successful outcome decode: %v", err)
	}
	if _, ok := procedure.Value.(*HandoverRequestAcknowledge); !ok {
		t.Fatalf("decoded outcome type = %T, want *HandoverRequestAcknowledge", procedure.Value)
	}
	if len(procedure.ProtocolIEs) != 4 {
		t.Fatalf("decoded outcome IEs = %#v, want four", procedure.ProtocolIEs)
	}
	admitted := procedure.ProtocolIEs[2]
	if admitted.ObjectSet != "HandoverRequestAcknowledge-IEs" || admitted.Field.Id != IdERABsAdmittedList {
		t.Fatalf("admitted-list context = (%q, %d)", admitted.ObjectSet, admitted.Field.Id)
	}
	if len(admitted.Children) != 1 {
		t.Fatalf("admitted-list children = %#v, want one", admitted.Children)
	}
	itemNode := admitted.Children[0]
	if itemNode.ObjectSet != "E-RABs-Admitted-ItemIEs" || itemNode.Field.Id != IdERABsAdmittedItem {
		t.Fatalf("admitted-item context = (%q, %d)", itemNode.ObjectSet, itemNode.Field.Id)
	}
	item, ok := itemNode.Value.(*ERABsAdmittedItem)
	if !ok || item.ERABID != 5 {
		t.Fatalf("admitted item = %#v, want E-RAB 5", itemNode.Value)
	}
	if len(itemNode.Extensions) != 1 {
		t.Fatalf("admitted-item extensions = %#v, want one", itemNode.Extensions)
	}
	extension := itemNode.Extensions[0]
	wantPath := "HandoverRequestAcknowledge.ProtocolIEs[2][0].IEExtensions[0]"
	if extension.Path != wantPath || extension.ObjectSet != "E-RABs-Admitted-Item-ExtIEs" || extension.Field.Id != IdDAPSResponseInfo {
		t.Errorf("extension context = (%q, %q, %d), want (%q, E-RABs-Admitted-Item-ExtIEs, 366)",
			extension.Path, extension.ObjectSet, extension.Field.Id, wantPath)
	}
	if !bytes.Equal(extension.Field.ExtensionValue.Bytes, dapsWire) {
		t.Errorf("retained DAPS bytes = %x, want %x", extension.Field.ExtensionValue.Bytes, dapsWire)
	}
	daps, ok := extension.Value.(*DAPSResponseInfo)
	if !ok || daps.DAPSResponseIndicator != 0 {
		t.Errorf("decoded DAPS response = %#v, want accepted", extension.Value)
	}
}

func TestDecodeProtocolExtensionFieldsRecursivePreservesUnknownExtension(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	decoded, err := DecodeProtocolExtensionFieldsRecursive(
		"E-RABs-Admitted-Item-ExtIEs",
		[]ProtocolExtensionField{{Id: 65532, ExtensionValue: runtime.RawValue{Bytes: raw}}},
	)
	if err != nil {
		t.Fatalf("unknown extension decode: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Value != nil {
		t.Fatalf("unknown extension result = %#v, want one unresolved node", decoded)
	}
	if !bytes.Equal(decoded[0].Field.ExtensionValue.Bytes, raw) {
		t.Errorf("unknown extension bytes = %x, want %x", decoded[0].Field.ExtensionValue.Bytes, raw)
	}
}

func TestDecodeProtocolExtensionsRecursiveReportsDAPSPath(t *testing.T) {
	item := &ERABsAdmittedItem{
		IEExtensions: ProtocolExtensionContainer{{Id: IdDAPSResponseInfo}},
	}
	_, err := DecodeProtocolExtensionsRecursive(item)
	if err == nil ||
		!strings.Contains(err.Error(), "ERABsAdmittedItem.IEExtensions[0]") ||
		!strings.Contains(err.Error(), "E-RABs-Admitted-Item-ExtIEs") ||
		!strings.Contains(err.Error(), "extension 366") {
		t.Fatalf("malformed DAPS extension error = %v, want full path, object set, and ID", err)
	}
}

func TestDAPSResponseInfoExtensionRoundTrip(t *testing.T) {
	original, err := (&DAPSResponseInfo{DAPSResponseIndicator: 0}).MarshalAPER()
	if err != nil {
		t.Fatalf("encoding DAPS response: %v", err)
	}
	decoded, err := DecodeExtensionFieldValue("E-RABs-Admitted-Item-ExtIEs", IdDAPSResponseInfo, original)
	if err != nil {
		t.Fatalf("decoding DAPS response extension: %v", err)
	}
	daps, ok := decoded.(*DAPSResponseInfo)
	if !ok {
		t.Fatalf("decoded DAPS response type = %T, want *DAPSResponseInfo", decoded)
	}
	reencoded, err := daps.MarshalAPER()
	if err != nil {
		t.Fatalf("re-encoding DAPS response: %v", err)
	}
	if !bytes.Equal(reencoded, original) {
		t.Errorf("DAPS response round trip = %x, want %x", reencoded, original)
	}
}

func FuzzDecodeProtocolExtensionFieldsRecursive(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeProtocolExtensionFieldsRecursive(
			"E-RABs-Admitted-Item-ExtIEs",
			[]ProtocolExtensionField{{
				Id:             IdDAPSResponseInfo,
				ExtensionValue: runtime.RawValue{Bytes: raw},
			}},
		)
	})
}
