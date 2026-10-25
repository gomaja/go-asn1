// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestTableSelectedOpenTypeDepth(t *testing.T) {
	cause := causeapiMust(s00.NewCauseMisc(s00.CauseMiscUnspecified))
	body := x2SetupFailureapiMust(s14.NewX2SetupFailure(s07.X2SetupFailureIEContainer{x2SetupFailureIEFieldapiMust(s07.X2SetupFailureIEs().Cause().New(cause))}))
	message := unsuccessfulOutcomeapiMust(s21.X2SetupProcedure().Unsuccessful().Build(body))
	pdu := x2APPDUapiMust(s21.NewX2APPDUUnsuccessfulOutcome(message))
	wire := listByteapiMust(pdu.MarshalAPER())
	state := aper.ApplyDecodeOptions()
	var shallow s20.X2APPDU
	if err := s20.X2apInternalX2APPDUUnmarshalAPERWithOptions(&shallow, wire, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 2 {
		t.Fatalf("table-selected scopes=%+v", usage)
	}
	var limited s20.X2APPDU
	if _, err := limited.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxDepth: 1})); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("depth limit: %v", err)
	}

	// A table-selected GlobalENBID contains a known ENBID CHOICE addition.
	// Its open type must remain nested inside the selected IE's scope.
	enb := eNBIDapiMust(s00.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	global := s05.GlobalENBID{PLMNIdentity: make([]byte, 3), ENBID: enb}
	field := x2SetupRequestIEFieldapiMust(s17.X2SetupRequestIEs().GlobalENBID().New(global))
	request := s20.X2SetupRequest{ProtocolIEs: s17.X2SetupRequestIEContainer{field}}
	outer := s20.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &s20.InitiatingMessage{ProcedureCode: s00.IdX2Setup, Criticality: s00.CriticalityReject, Value: s20.X2apInternalConstructT15InitiatingValueF4codeF18bodyX2SetupRequest(s00.IdX2Setup, &request)}}
	deeper := listByteapiMust(outer.MarshalAPER())
	state = aper.ApplyDecodeOptions()
	var nested s20.X2APPDU
	if err := s20.X2apInternalX2APPDUUnmarshalAPERWithOptions(&nested, deeper, state); err != nil {
		t.Fatal(err)
	}
	if usage := state.Usage(); usage.MaxOpenTypeDepth != 3 {
		t.Fatalf("nested CHOICE scopes=%+v", usage)
	}
}
