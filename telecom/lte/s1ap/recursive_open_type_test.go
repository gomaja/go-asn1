package s1ap

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

func TestDecodeProtocolIEsRecursivePagingTAIList(t *testing.T) {
	// 3GPP TS 36.413 V19.2.0, S1AP-PDU-Contents:
	// TAIList applies TAIItemIEs to each ProtocolIE-SingleContainer.
	itemWire, err := (&TAIItem{TAI: TAI{
		PLMNidentity: PLMNidentity{0x01, 0xf0, 0x10},
		TAC:          TAC{0x12, 0x34},
	}}).MarshalAPER()
	if err != nil {
		t.Fatalf("encoding TAI item: %v", err)
	}

	list := per.NewBitBuffer()
	if err := per.EncodeConstrainedWholeNumberAligned(list, 1, 1, 256); err != nil {
		t.Fatalf("encoding TAI list length: %v", err)
	}
	if err := (&ProtocolIEField{
		Id: IdTAIItem, Criticality: CriticalityIgnore,
		Value: runtime.RawValue{Bytes: itemWire},
	}).MarshalAPERTo(list); err != nil {
		t.Fatalf("encoding TAI list item: %v", err)
	}

	paging := &Paging{ProtocolIEs: ProtocolIEContainer{{
		Id: IdTAIList, Criticality: CriticalityIgnore,
		Value: runtime.RawValue{Bytes: list.Bytes()},
	}}}
	decoded, err := DecodeProtocolIEsRecursive(paging)
	if err != nil {
		t.Fatalf("recursive Paging decode: %v", err)
	}
	if len(decoded) != 1 || len(decoded[0].Children) != 1 {
		t.Fatalf("decoded Paging tree = %#v, want one TAIList root and one TAIItem child", decoded)
	}
	if decoded[0].ObjectSet != "PagingIEs" || decoded[0].Children[0].ObjectSet != "TAIItemIEs" {
		t.Errorf("object-set chain = %q -> %q, want PagingIEs -> TAIItemIEs",
			decoded[0].ObjectSet, decoded[0].Children[0].ObjectSet)
	}
	item, ok := decoded[0].Children[0].Value.(*TAIItem)
	if !ok {
		t.Fatalf("decoded nested value type = %T, want *TAIItem", decoded[0].Children[0].Value)
	}
	if !bytes.Equal(item.TAI.PLMNidentity, []byte{0x01, 0xf0, 0x10}) || !bytes.Equal(item.TAI.TAC, []byte{0x12, 0x34}) {
		t.Errorf("decoded TAI = %#v", item.TAI)
	}

	pagingWire, err := paging.MarshalAPER()
	if err != nil {
		t.Fatalf("encoding Paging value: %v", err)
	}
	wrapper := &InitiatingMessage{
		ProcedureCode: IdPaging,
		Criticality:   int64(CriticalityIgnore),
		Value:         runtime.RawValue{Bytes: pagingWire},
	}
	procedure, err := wrapper.DecodeValueRecursive()
	if err != nil {
		t.Fatalf("recursive procedure decode: %v", err)
	}
	if _, ok := procedure.Value.(*Paging); !ok {
		t.Fatalf("decoded procedure value type = %T, want *Paging", procedure.Value)
	}
	if len(procedure.ProtocolIEs) != 1 || len(procedure.ProtocolIEs[0].Children) != 1 {
		t.Fatalf("decoded procedure tree = %#v, want one TAIList root and one TAIItem child", procedure.ProtocolIEs)
	}
}

func TestDecodeProtocolIEsRecursiveResetAcknowledgeConnectionList(t *testing.T) {
	mmeID := MMEUES1APID(7)
	enbID := ENBUES1APID(9)
	itemWire, err := (&UEAssociatedLogicalS1ConnectionItem{
		MMEUES1APID: &mmeID,
		ENBUES1APID: &enbID,
	}).MarshalAPER()
	if err != nil {
		t.Fatalf("encoding connection item: %v", err)
	}

	list := per.NewBitBuffer()
	if err := per.EncodeConstrainedWholeNumberAligned(list, 1, 1, 256); err != nil {
		t.Fatalf("encoding connection list length: %v", err)
	}
	if err := (&ProtocolIEField{
		Id: IdUEAssociatedLogicalS1ConnectionItem, Criticality: CriticalityReject,
		Value: runtime.RawValue{Bytes: itemWire},
	}).MarshalAPERTo(list); err != nil {
		t.Fatalf("encoding connection list item: %v", err)
	}

	reset := &ResetAcknowledge{ProtocolIEs: ProtocolIEContainer{{
		Id: IdUEAssociatedLogicalS1ConnectionListResAck, Criticality: CriticalityIgnore,
		Value: runtime.RawValue{Bytes: list.Bytes()},
	}}}
	decoded, err := DecodeProtocolIEsRecursive(reset)
	if err != nil {
		t.Fatalf("recursive ResetAcknowledge decode: %v", err)
	}
	if len(decoded) != 1 || len(decoded[0].Children) != 1 {
		t.Fatalf("decoded ResetAcknowledge tree = %#v, want one list root and one item child", decoded)
	}
	if decoded[0].ObjectSet != "ResetAcknowledgeIEs" || decoded[0].Children[0].ObjectSet != "UE-associatedLogicalS1-ConnectionItemResAck" {
		t.Errorf("object-set chain = %q -> %q, want ResetAcknowledgeIEs -> UE-associatedLogicalS1-ConnectionItemResAck",
			decoded[0].ObjectSet, decoded[0].Children[0].ObjectSet)
	}
	item, ok := decoded[0].Children[0].Value.(*UEAssociatedLogicalS1ConnectionItem)
	if !ok {
		t.Fatalf("decoded nested value type = %T, want *UEAssociatedLogicalS1ConnectionItem", decoded[0].Children[0].Value)
	}
	if item.MMEUES1APID == nil || *item.MMEUES1APID != mmeID || item.ENBUES1APID == nil || *item.ENBUES1APID != enbID {
		t.Errorf("decoded connection item = %#v, want MME/eNB IDs %d/%d", item, mmeID, enbID)
	}
}

func FuzzDecodeProtocolIEFieldsRecursive(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeProtocolIEFieldsRecursive("TAIItemIEs", []ProtocolIEField{{
			Id: IdTAIItem, Criticality: CriticalityIgnore, Value: runtime.RawValue{Bytes: raw},
		}})
	})
}
