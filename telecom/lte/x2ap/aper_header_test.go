package x2ap

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

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
