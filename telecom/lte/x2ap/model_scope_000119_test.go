// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestNestedWithoutReplayCopy(t *testing.T) {
	value := eNBIDapiMust(s00.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	preferred := listByteapiMust(value.MarshalAPER())
	wire := append([]byte(nil), preferred...)
	malformed := bytes.Clone(wire)
	malformed[len(malformed)-1] |= 1
	var rejected s00.ENBID
	if _, err := rejected.UnmarshalAPER(malformed); err == nil {
		t.Fatal("nonzero known CHOICE padding accepted")
	}
	var original s00.ENBID
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if got := listByteapiMust(original.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, preferred) {
		t.Fatalf("fresh CHOICE padding = %x, preferred = %x", got, preferred)
	}
	sibling := original
	copy := original.WithoutReplay()
	parent := s05.GlobalENBID{PLMNIdentity: make([]byte, 3), ENBID: copy}
	got := listByteapiMust(parent.MarshalAPER())
	want := listByteapiMust(parent.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) {
		t.Fatalf("nested fresh copy = %x, option = %x", got, want)
	}
	for _, v := range []*s00.ENBID{&original, &sibling} {
		if !bytes.Equal(listByteapiMust(v.MarshalAPER()), wire) {
			t.Fatal("copy changed original or sibling replay")
		}
	}
	// A nested fresh request must pass through selected IE and procedure unions.
	field := x2SetupRequestIEFieldapiMust(s17.X2SetupRequestIEs().GlobalENBID().New(parent))
	body := s19.X2SetupRequest{ProtocolIEs: s17.X2SetupRequestIEContainer{field}}
	outer := s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &s19.InitiatingMessage{ProcedureCode: s00.IdX2Setup, Criticality: s00.CriticalityReject, Value: s19.X2apInternalConstructT15InitiatingValueF4codeF18bodyX2SetupRequest(s00.IdX2Setup, &body)}}
	if got, want := listByteapiMust(outer.MarshalAPER()), listByteapiMust(outer.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("table fresh copy = %x, option = %x", got, want)
	}
	body.ProtocolIEs[0] = x2SetupRequestIEFieldapiMust(s17.X2SetupRequestIEs().GlobalENBID().New(s05.GlobalENBID{PLMNIdentity: make([]byte, 3), ENBID: original}))
	outerWire := listByteapiMust(outer.MarshalAPER())
	var received s19.X2APPDU
	if _, err := received.UnmarshalAPER(outerWire); err != nil {
		t.Fatal(err)
	}
	receivedBody, _ := received.InitiatingMessage.Value.AsX2SetupRequest()
	receivedGlobal, _ := receivedBody.ProtocolIEs[0].Value.AsGlobalENBID()
	receivedGlobal.ENBID = receivedGlobal.ENBID.WithoutReplay()
	if got, want := listByteapiMust(received.MarshalAPER()), listByteapiMust(received.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("received parent replayed fresh copy: %x, option %x", got, want)
	}
}
