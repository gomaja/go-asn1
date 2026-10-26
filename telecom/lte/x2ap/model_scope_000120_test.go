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

func TestNestedWithoutReplaySequenceBitmap(t *testing.T) {
	cd := s06.CriticalityDiagnostics{}
	if err := cd.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s06.X2apInternalCriticalityDiagnosticsFieldExtCount(&cd) = 3
	*s06.X2apInternalCriticalityDiagnosticsFieldExtPresent(&cd) = append(*s06.X2apInternalCriticalityDiagnosticsFieldExtPresent(&cd), false, false, false)
	*s06.X2apInternalCriticalityDiagnosticsFieldExtData(&cd) = append(*s06.X2apInternalCriticalityDiagnosticsFieldExtData(&cd), nil, nil, nil)
	wire := listByteapiMust(cd.MarshalAPER())
	var original s06.CriticalityDiagnostics
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	field := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().CriticalityDiagnostics().New(original))
	body := s19.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{field}}
	outer := s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &s19.InitiatingMessage{ProcedureCode: s00.IdErrorIndication, Criticality: s00.CriticalityIgnore, Value: s19.X2apInternalConstructT15InitiatingValueF4codeF19bodyErrorIndication(s00.IdErrorIndication, &body)}}
	parentWire := listByteapiMust(outer.MarshalAPER())
	var received s19.X2APPDU
	if _, err := received.UnmarshalAPER(parentWire); err != nil {
		t.Fatal(err)
	}
	for _, source := range []s19.X2APPDU{received, outer} {
		copy := source.WithoutReplay()
		if got, want := listByteapiMust(copy.MarshalAPER()), listByteapiMust(source.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
			t.Fatalf("root copy = %x, option = %x", got, want)
		}
	}
	fresh := original.WithoutReplay()
	body.ProtocolIEs[0] = errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().CriticalityDiagnostics().New(fresh))
	if got, want := listByteapiMust(outer.MarshalAPER()), listByteapiMust(outer.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("nested bitmap = %x, option = %x", got, want)
	}
	if !bytes.Equal(listByteapiMust(original.MarshalAPER()), wire) {
		t.Fatal("fresh copy changed original bitmap")
	}
	if !bytes.Equal(listByteapiMust(received.MarshalAPER()), parentWire) {
		t.Fatal("fresh copy changed received parent")
	}
}
