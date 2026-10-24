// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestTableSelectedOpenTypeDepth(t *testing.T) {
	cause := causeFreshMust(s25.NewCauseMisc(s00.CauseMiscUnspecified))
	body := s1SetupFailureFreshMust(s49.NewS1SetupFailure(s23.S1SetupFailureIEContainer{s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().Cause().New(cause))}))
	message := unsuccessfulOutcomeFreshMust(s52.S1SetupProcedure().Unsuccessful().Build(body))
	pdu := s1APPDUFreshMust(s52.NewS1APPDUUnsuccessfulOutcome(message))
	wire := sliceByteFreshMust(pdu.MarshalAPER())
	state := aper.ApplyDecodeOptions()
	var shallow s52.S1APPDU
	if err := s52.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&shallow, wire, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 2 {
		t.Fatalf("table-selected scopes=%+v", usage)
	}
	var limited s52.S1APPDU
	if _, err := limited.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxDepth: 1})); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("depth limit: %v", err)
	}

	// A table-selected GlobalENBID contains a known ENBID CHOICE addition.
	// Its open type must remain nested inside the selected IE's scope.
	enb := eNBIDFreshMust(s25.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	global := s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: enb}
	field := s1SetupRequestIEFieldFreshMust(s43.S1SetupRequestIEs().GlobalENBID().New(global))
	request := s43.S1SetupRequest{ProtocolIEs: s43.S1SetupRequestIEContainer{field}}
	outer := s52.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &s51.InitiatingMessage{ProcedureCode: s00.IdS1Setup, Criticality: s00.CriticalityReject, Value: func() s51.InitiatingValue {
		sealed := s51.InitiatingValue{}
		*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.IdS1Setup
		*s51.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &request
		return sealed
	}()}}
	deeper := sliceByteFreshMust(outer.MarshalAPER())
	state = aper.ApplyDecodeOptions()
	var nested s52.S1APPDU
	if err := s52.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&nested, deeper, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 3 {
		t.Fatalf("nested CHOICE scopes=%+v", usage)
	}
}
func TestZeroProcedureBindingsRefuse(t *testing.T) {
	var initiating s51.ErrorIndicationInitiatingBinding
	if _, err := initiating.Build(s28.ErrorIndication{}); err == nil {
		t.Fatal("zero initiating binding accepted")
	}
	var successful s50.S1SetupResponseSuccessfulBinding
	if _, err := successful.Build(s43.S1SetupResponse{}); err == nil {
		t.Fatal("zero successful binding accepted")
	}
	var unsuccessful s36.S1SetupFailureUnsuccessfulBinding
	if _, err := unsuccessful.Build(s26.S1SetupFailure{}); err == nil {
		t.Fatal("zero unsuccessful binding accepted")
	}
}
