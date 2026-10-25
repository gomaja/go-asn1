// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	testing "testing"
)

func TestGenericFieldReceivedFormKeepsSourcePath(t *testing.T) {
	field := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	initial := s20.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{field}}
	var received s20.ErrorIndication
	if _, err := received.UnmarshalAPER(listByteapiMust(initial.MarshalAPER())); err != nil {
		t.Fatal(err)
	}
	if got := received.ProtocolIEs[0].ReceivedForm().Location().Path; got != "ProtocolIEField" {
		t.Errorf("IE path=%q", got)
	}
	diagnostics := s06.CriticalityDiagnostics{IEExtensions: s02.CriticalityDiagnosticsExtIEsExtContainer{criticalityDiagnosticsExtIEsExtFieldapiMust(s06.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))}}
	var next s06.CriticalityDiagnostics
	if _, err := next.UnmarshalAPER(listByteapiMust(diagnostics.MarshalAPER())); err != nil {
		t.Fatal(err)
	}
	if got := next.IEExtensions[0].ReceivedForm().Location().Path; got != "ProtocolExtensionField" {
		t.Errorf("extension path=%q", got)
	}
	private := privateMessageapiMust(s20.NewPrivateMessage(s00.PrivateMessageIEsValuePrivateIEContainer{privateMessageIEsValuePrivateIEFieldapiMust(s00.PrivateMessageIEs().NewOpaque(privateIEIDapiMust(s00.NewPrivateIEIDLocal(1)), s00.CriticalityIgnore, []byte{0}))}))
	var message s20.PrivateMessage
	if _, err := message.UnmarshalAPER(listByteapiMust(private.MarshalAPER())); err != nil {
		t.Fatal(err)
	}
	if got := message.PrivateIEs[0].ReceivedForm().Location().Path; got != "PrivateIEField" {
		t.Errorf("private path=%q", got)
	}
}
