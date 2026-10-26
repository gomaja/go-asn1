// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	s67 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s67"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestTableSelectedOpenTypeDepth(t *testing.T) {
	cause := causeFreshMust(s30.NewCauseMisc(s00.CauseMiscUnspecified))
	body := s1SetupFailureFreshMust(s62.NewS1SetupFailure(s27.S1SetupFailureIEContainer{s1SetupFailureIEFieldFreshMust(s27.S1SetupFailureIEs().Cause().New(cause))}))
	message := unsuccessfulOutcomeFreshMust(s66.S1SetupProcedure().Unsuccessful().Build(body))
	pdu := s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(message))
	wire := sliceByteFreshMust(pdu.MarshalAPER())
	state := aper.ApplyDecodeOptions()
	var shallow s66.S1APPDU
	if err := s66.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&shallow, wire, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 2 {
		t.Fatalf("table-selected scopes=%+v", usage)
	}
	var limited s66.S1APPDU
	if _, err := limited.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxDepth: 1})); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("depth limit: %v", err)
	}

	// A table-selected GlobalENBID contains a known ENBID CHOICE addition.
	// Its open type must remain nested inside the selected IE's scope.
	enb := eNBIDFreshMust(s30.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	global := s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: enb}
	field := s1SetupRequestIEFieldFreshMust(s54.S1SetupRequestIEs().GlobalENBID().New(global))
	request := s54.S1SetupRequest{ProtocolIEs: s54.S1SetupRequestIEContainer{field}}
	outer := s66.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &s65.InitiatingMessage{ProcedureCode: s00.IdS1Setup, Criticality: s00.CriticalityReject, Value: func() s65.InitiatingValue {
		sealed := s65.InitiatingValue{}
		*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.IdS1Setup
		*s65.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &request
		return sealed
	}()}}
	deeper := sliceByteFreshMust(outer.MarshalAPER())
	state = aper.ApplyDecodeOptions()
	var nested s66.S1APPDU
	if err := s66.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&nested, deeper, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 3 {
		t.Fatalf("nested CHOICE scopes=%+v", usage)
	}
}
func TestZeroProcedureBindingsRefuse(t *testing.T) {
	var initiating s65.ErrorIndicationInitiatingBinding
	if _, err := initiating.Build(s36.ErrorIndication{}); err == nil {
		t.Fatal("zero initiating binding accepted")
	}
	var successful s64.S1SetupResponseSuccessfulBinding
	if _, err := successful.Build(s54.S1SetupResponse{}); err == nil {
		t.Fatal("zero successful binding accepted")
	}
	var unsuccessful s46.S1SetupFailureUnsuccessfulBinding
	if _, err := unsuccessful.Build(s31.S1SetupFailure{}); err == nil {
		t.Fatal("zero unsuccessful binding accepted")
	}
}
