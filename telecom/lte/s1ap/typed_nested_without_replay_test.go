// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestNestedWithoutReplayCopy(t *testing.T) {
	value := eNBIDFreshMust(s30.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	preferred := sliceByteFreshMust(value.MarshalAPER())
	wire := append([]byte(nil), preferred...)
	var original s18.ENBID
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	copy := original.WithoutReplay()
	parent := s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: copy}
	got := sliceByteFreshMust(parent.MarshalAPER())
	want := sliceByteFreshMust(parent.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) {
		t.Fatalf("nested fresh copy = %x, option = %x", got, want)
	}
	if got := sliceByteFreshMust(original.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("copy changed original replay")
	}

	// The same source value passes through a table union and an outcome body.
	field := s1SetupRequestIEFieldFreshMust(s54.S1SetupRequestIEs().GlobalENBID().New(parent))
	body := s54.S1SetupRequest{ProtocolIEs: s54.S1SetupRequestIEContainer{field}}
	outer := s66.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &s65.InitiatingMessage{ProcedureCode: s00.IdS1Setup, Criticality: s00.CriticalityReject, Value: func() s65.InitiatingValue {
		sealed := s65.InitiatingValue{}
		*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.IdS1Setup
		*s65.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &body
		return sealed
	}()}}
	if got, want := sliceByteFreshMust(outer.MarshalAPER()), sliceByteFreshMust(outer.MarshalAPER(aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("table fresh copy = %x, option = %x", got, want)
	}
	// Put the copy into an already received parent, whose enclosing unions
	// can otherwise replay their own preserved contents.
	body.ProtocolIEs[0] = s1SetupRequestIEFieldFreshMust(s54.S1SetupRequestIEs().GlobalENBID().New(s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: original}))
	outerWire := sliceByteFreshMust(outer.MarshalAPER())
	var received s66.S1APPDU
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
	enb := eNBIDFreshMust(s30.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))
	global := s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: enb}
	if err := global.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s21.BridgeGlobalENBIDFieldExtCount(&global) = 3
	*s21.BridgeGlobalENBIDFieldExtPresent(&global) = append(*s21.BridgeGlobalENBIDFieldExtPresent(&global), false, false, false)
	*s21.BridgeGlobalENBIDFieldExtData(&global) = append(*s21.BridgeGlobalENBIDFieldExtData(&global), nil, nil, nil)
	wire := sliceByteFreshMust(global.MarshalAPER())
	var original s21.GlobalENBID
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	parent := s43.TargeteNBID{GlobalENBID: original.WithoutReplay(), SelectedTAI: s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}
	got := sliceByteFreshMust(parent.MarshalAPER())
	want := sliceByteFreshMust(parent.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) {
		t.Fatalf("nested sequence bitmap = %x, option = %x", got, want)
	}
	if got := sliceByteFreshMust(original.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("fresh copy changed original bitmap")
	}
}
