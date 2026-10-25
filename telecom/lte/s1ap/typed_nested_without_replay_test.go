// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestNestedWithoutReplayCopy(t *testing.T) {
	value := eNBIDFreshMust(s25.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	preferred := sliceByteFreshMust(value.MarshalAPER())
	wire := append([]byte(nil), preferred...)
	var original s15.ENBID
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	copy := original.WithoutReplay()
	parent := s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: copy}
	got := sliceByteFreshMust(parent.MarshalAPER())
	want := sliceByteFreshMust(parent.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) {
		t.Fatalf("nested fresh copy = %x, option = %x", got, want)
	}
	if got := sliceByteFreshMust(original.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("copy changed original replay")
	}

	// The same source value passes through a table union and an outcome body.
	field := s1SetupRequestIEFieldFreshMust(s43.S1SetupRequestIEs().GlobalENBID().New(parent))
	body := s44.S1SetupRequest{ProtocolIEs: s43.S1SetupRequestIEContainer{field}}
	outer := s52.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &s51.InitiatingMessage{ProcedureCode: s00.IdS1Setup, Criticality: s00.CriticalityReject, Value: func() s51.InitiatingValue {
		sealed := s51.InitiatingValue{}
		*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.IdS1Setup
		*s51.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &body
		return sealed
	}()}}
	if got, want := sliceByteFreshMust(outer.MarshalAPER()), sliceByteFreshMust(outer.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("table fresh copy = %x, option = %x", got, want)
	}
	// Put the copy into an already received parent, whose enclosing unions
	// can otherwise replay their own preserved contents.
	body.ProtocolIEs[0] = s1SetupRequestIEFieldFreshMust(s43.S1SetupRequestIEs().GlobalENBID().New(s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: original}))
	outerWire := sliceByteFreshMust(outer.MarshalAPER())
	var received s52.S1APPDU
	if _, err := received.UnmarshalAPER(outerWire); err != nil {
		t.Fatal(err)
	}
	receivedBody, _ := received.InitiatingMessage.Value.AsS1SetupRequest()
	receivedGlobal, _ := receivedBody.ProtocolIEs[0].Value.AsGlobalENBID()
	receivedGlobal.ENBID = receivedGlobal.ENBID.WithoutReplay()
	if got, want := sliceByteFreshMust(received.MarshalAPER()), sliceByteFreshMust(received.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("received parent replayed nested fresh copy: %x, option %x", got, want)
	}
}
func TestNestedWithoutReplaySequenceBitmap(t *testing.T) {
	enb := eNBIDFreshMust(s25.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))
	global := s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: enb}
	if err := global.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s18.BridgeGlobalENBIDFieldExtCount(&global) = 3
	*s18.BridgeGlobalENBIDFieldExtPresent(&global) = append(*s18.BridgeGlobalENBIDFieldExtPresent(&global), false, false, false)
	*s18.BridgeGlobalENBIDFieldExtData(&global) = append(*s18.BridgeGlobalENBIDFieldExtData(&global), nil, nil, nil)
	wire := sliceByteFreshMust(global.MarshalAPER())
	var original s18.GlobalENBID
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	parent := s34.TargeteNBID{GlobalENBID: original.WithoutReplay(), SelectedTAI: s31.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}
	got := sliceByteFreshMust(parent.MarshalAPER())
	want := sliceByteFreshMust(parent.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) {
		t.Fatalf("nested sequence bitmap = %x, option = %x", got, want)
	}
	if got := sliceByteFreshMust(original.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("fresh copy changed original bitmap")
	}
}
