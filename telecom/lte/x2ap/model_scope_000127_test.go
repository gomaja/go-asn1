// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestReceivedAncestorHonorsNestedFreshBitmap(t *testing.T) {
	diagnostics := s06.CriticalityDiagnostics{}
	if err := diagnostics.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s06.X2apInternalCriticalityDiagnosticsFieldExtCount(&diagnostics) = 3
	*s06.X2apInternalCriticalityDiagnosticsFieldExtPresent(&diagnostics) = append(*s06.X2apInternalCriticalityDiagnosticsFieldExtPresent(&diagnostics), false, false, false)
	*s06.X2apInternalCriticalityDiagnosticsFieldExtData(&diagnostics) = append(*s06.X2apInternalCriticalityDiagnosticsFieldExtData(&diagnostics), nil, nil, nil)
	field := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().CriticalityDiagnostics().New(diagnostics))
	body := s19.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{field}}
	original := s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &s19.InitiatingMessage{ProcedureCode: s00.IdErrorIndication, Criticality: s00.CriticalityIgnore, Value: s19.X2apInternalConstructT15InitiatingValueF4codeF19bodyErrorIndication(s00.IdErrorIndication, &body)}}
	wire := listByteapiMust(original.MarshalAPER())
	var received s19.X2APPDU
	if _, err := received.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	decoded, _ := received.InitiatingMessage.Value.AsErrorIndication()
	value, _ := decoded.ProtocolIEs[0].Value.AsCriticalityDiagnostics()
	*value = value.WithoutReplay()
	got := listByteapiMust(received.MarshalAPER())
	want := listByteapiMust(received.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatal("received parent replayed nested fresh copy")
	}
}
