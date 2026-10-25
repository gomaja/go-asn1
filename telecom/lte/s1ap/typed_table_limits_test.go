// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestTableSelectedOpenTypeDepth(t *testing.T) {
	cause := causeFreshMust(s26.NewCauseMisc(s00.CauseMiscUnspecified))
	body := s1SetupFailureFreshMust(s50.NewS1SetupFailure(s23.S1SetupFailureIEContainer{s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().Cause().New(cause))}))
	message := unsuccessfulOutcomeFreshMust(s53.S1SetupProcedure().Unsuccessful().Build(body))
	pdu := s1APPDUFreshMust(s53.NewS1APPDUUnsuccessfulOutcome(message))
	wire := sliceByteFreshMust(pdu.MarshalAPER())
	state := aper.ApplyDecodeOptions()
	var shallow s53.S1APPDU
	if err := s53.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&shallow, wire, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 2 {
		t.Fatalf("table-selected scopes=%+v", usage)
	}
	var limited s53.S1APPDU
	if _, err := limited.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxDepth: 1})); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("depth limit: %v", err)
	}

	// A table-selected GlobalENBID contains a known ENBID CHOICE addition.
	// Its open type must remain nested inside the selected IE's scope.
	enb := eNBIDFreshMust(s26.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	global := s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: enb}
	field := s1SetupRequestIEFieldFreshMust(s44.S1SetupRequestIEs().GlobalENBID().New(global))
	request := s44.S1SetupRequest{ProtocolIEs: s44.S1SetupRequestIEContainer{field}}
	outer := s53.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &s52.InitiatingMessage{ProcedureCode: s00.IdS1Setup, Criticality: s00.CriticalityReject, Value: func() s52.InitiatingValue {
		sealed := s52.InitiatingValue{}
		*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.IdS1Setup
		*s52.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &request
		return sealed
	}()}}
	deeper := sliceByteFreshMust(outer.MarshalAPER())
	state = aper.ApplyDecodeOptions()
	var nested s53.S1APPDU
	if err := s53.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&nested, deeper, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 3 {
		t.Fatalf("nested CHOICE scopes=%+v", usage)
	}
}
func TestZeroProcedureBindingsRefuse(t *testing.T) {
	var initiating s52.ErrorIndicationInitiatingBinding
	if _, err := initiating.Build(s28.ErrorIndication{}); err == nil {
		t.Fatal("zero initiating binding accepted")
	}
	var successful s51.S1SetupResponseSuccessfulBinding
	if _, err := successful.Build(s44.S1SetupResponse{}); err == nil {
		t.Fatal("zero successful binding accepted")
	}
	var unsuccessful s37.S1SetupFailureUnsuccessfulBinding
	if _, err := unsuccessful.Build(s27.S1SetupFailure{}); err == nil {
		t.Fatal("zero unsuccessful binding accepted")
	}
}
