package x2ap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

func TestHandoverRequestUEHistoryInformationWireValue(t *testing.T) {
	// TS 36.423 V19.1.0 sections 9.1.1.1 and 9.2.38: HandoverRequest
	// IE 15, captured with nine visited E-UTRAN cells and independently decoded
	// by TShark 4.6.8.
	raw, err := hex.DecodeString("800006f730010840b10000050006f730010220c10000020006f730010840b10000010006f730010220c10000120006f730010840b10000070006f730010220c100000d0006f730010840b100001a0006f730010220c10000030006f730010840b1000062")
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	decoded, err := DecodeIEFieldValue("HandoverRequest", IdUEHistoryInformation, raw)
	if err != nil {
		t.Fatalf("DecodeIEFieldValue: %v", err)
	}
	history, ok := decoded.(*UEHistoryInformation)
	if !ok {
		t.Fatalf("decoded type: got %T, want *UEHistoryInformation", decoded)
	}
	wantTimes := []int64{5, 2, 1, 18, 7, 13, 26, 3, 98}
	if len(*history) != len(wantTimes) {
		t.Fatalf("decoded history length: got %d, want %d", len(*history), len(wantTimes))
	}
	for i, item := range *history {
		if item.Choice != LastVisitedCellItemChoiceEUTRANCell || item.EUTRANCell == nil {
			t.Fatalf("item %d choice: got %+v, want E-UTRAN cell", i, item)
		}
		if got := item.EUTRANCell.CellType.CellSize; got != CellSizeMedium {
			t.Errorf("item %d cell size: got %d (%s), want %d (%s)", i, got, got, CellSizeMedium, CellSizeMedium)
		}
		if got := item.EUTRANCell.TimeUEStayedInCell; got != wantTimes[i] {
			t.Errorf("item %d time stayed: got %d, want %d", i, got, wantTimes[i])
		}
	}
}

func TestProtocolIEFieldAPERHeaderUsesConstrainedLayout(t *testing.T) {
	field := ProtocolIEField{
		Id:          0x1234,
		Criticality: CriticalityIgnore,
		Value:       runtime.RawValue{Bytes: []byte{0xaa}},
	}

	got, err := field.MarshalAPER()
	if err != nil {
		t.Fatalf("MarshalAPER: %v", err)
	}
	want := []byte{0x12, 0x34, 0x40, 0x01, 0xaa}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded bytes: got % x, want % x", got, want)
	}

	var decoded ProtocolIEField
	if err := decoded.UnmarshalAPER(want); err != nil {
		t.Fatalf("UnmarshalAPER: %v", err)
	}
	if decoded.Id != field.Id || decoded.Criticality != field.Criticality || !bytes.Equal(decoded.Value.Bytes, field.Value.Bytes) {
		t.Fatalf("decoded field: got %+v, want %+v", decoded, field)
	}
}

func TestX2APPDUAPERHeaderUsesConstrainedLayout(t *testing.T) {
	pdu := NewX2APPDUInitiatingMessage(InitiatingMessage{
		ProcedureCode: 0x2e,
		Criticality:   int64(CriticalityReject),
		Value:         runtime.RawValue{Bytes: []byte{0xbb, 0xcc}},
	})

	got, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatalf("MarshalAPER: %v", err)
	}
	want := []byte{0x00, 0x2e, 0x00, 0x02, 0xbb, 0xcc}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded bytes: got % x, want % x", got, want)
	}

	var decoded X2APPDU
	if err := decoded.UnmarshalAPER(want); err != nil {
		t.Fatalf("UnmarshalAPER: %v", err)
	}
	if decoded.Choice != X2APPDUChoiceInitiatingMessage || decoded.InitiatingMessage == nil {
		t.Fatalf("decoded choice: got %d", decoded.Choice)
	}
	msg := decoded.InitiatingMessage
	if msg.ProcedureCode != pdu.InitiatingMessage.ProcedureCode ||
		msg.Criticality != pdu.InitiatingMessage.Criticality ||
		!bytes.Equal(msg.Value.Bytes, pdu.InitiatingMessage.Value.Bytes) {
		t.Fatalf("decoded message: got %+v, want %+v", *msg, *pdu.InitiatingMessage)
	}
}

func TestHandoverRequestIEValueDispatch(t *testing.T) {
	bb := per.NewBitBuffer()
	if err := per.EncodeIntegerAligned(bb, 7, int64Ptr(0), int64Ptr(4095), false); err != nil {
		t.Fatalf("encode UE-X2AP-ID: %v", err)
	}
	got, err := DecodeIEFieldValue("HandoverRequest", IdOldENBUEX2APID, bb.Bytes())
	if err != nil {
		t.Fatalf("DecodeIEFieldValue: %v", err)
	}
	ueID, ok := got.(*UEX2APID)
	if !ok {
		t.Fatalf("decoded type: got %T", got)
	}
	if *ueID != 7 {
		t.Fatalf("decoded UE-X2AP-ID: got %d, want 7", *ueID)
	}
}
