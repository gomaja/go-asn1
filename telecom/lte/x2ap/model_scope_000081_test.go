// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

func receiverUnknownWire(t *testing.T, count int) []byte {
	t.Helper()
	field, err := s11.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	fields := make(s11.ErrorIndicationIEContainer, count)
	for i := range fields {
		fields[i] = field
		fields[i], err = s11.ErrorIndicationIEs().NewOpaque(s00.ProtocolIEID(60000+i), s00.CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
	}
	body := s19.ErrorIndication{ProtocolIEs: fields}
	message := s19.InitiatingMessage{ProcedureCode: s00.IdErrorIndication, Criticality: s00.CriticalityIgnore, Value: s19.X2apInternalConstructT15InitiatingValueF4codeF19bodyErrorIndication(s00.IdErrorIndication, &body)}
	pdu := s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
