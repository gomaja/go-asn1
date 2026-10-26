// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// X2AP-PDU is one extensible CHOICE (TS 36.423 V19.1.0 §9.3.3;
// X.691 (02/2021) §23). Validation rejects contradictory in-memory arms
// through its existing error return, before dispatching a selected body.
func TestValidateMessagePDUChoiceStates(t *testing.T) {
	initiating := initiatingMessageapiMust(s19.ErrorIndicationProcedure().Initiating().Build(s19.ErrorIndication{}))
	successful := successfulOutcomeapiMust(s19.ResetProcedure().Successful().Build(s18.ResetResponse{}))
	failure := x2SetupFailureapiMust(s14.NewX2SetupFailure(s07.X2SetupFailureIEContainer{x2SetupFailureIEFieldapiMust(s07.X2SetupFailureIEs().Cause().New(apiCause()))}))
	unsuccessful := unsuccessfulOutcomeapiMust(s20.X2SetupProcedure().Unsuccessful().Build(failure))
	extension := choiceExtensionapiMust(aper.NewChoiceExtension(0, []byte{0}))
	cases := []struct {
		name  string
		value *s19.X2APPDU
	}{
		{"nil PDU", nil},
		{"zero choice", &s19.X2APPDU{}},
		{"negative choice", &s19.X2APPDU{Choice: -1}},
		{"unsupported extension choice", &s19.X2APPDU{Choice: 4}},
		{"nil initiating arm", &s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage}},
		{"nil successful arm", &s19.X2APPDU{Choice: s00.X2APPDUChoiceSuccessfulOutcome}},
		{"nil unsuccessful arm", &s19.X2APPDU{Choice: s00.X2APPDUChoiceUnsuccessfulOutcome}},
		{"conflicting initiating", &s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &initiating, UnknownExtension: &extension}},
		{"conflicting successful", &s19.X2APPDU{Choice: s00.X2APPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &successful, UnknownExtension: &extension}},
		{"conflicting unsuccessful", &s19.X2APPDU{Choice: s00.X2APPDUChoiceUnsuccessfulOutcome, UnsuccessfulOutcome: &unsuccessful, UnknownExtension: &extension}},
		{"conflicting unsupported choice", &s19.X2APPDU{Choice: 4, UnknownExtension: &extension}},
		{"conflicting negative choice", &s19.X2APPDU{Choice: -1, UnknownExtension: &extension}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, options := range [][]aper.EncodeOption{nil, {aper.WithoutReplay()}} {
				if _, err := tc.value.MarshalAPER(options...); err == nil {
					t.Fatal("test state is encodable")
				}
			}
			report, err := s20.ValidateMessage(tc.value)
			if err == nil {
				t.Fatalf("validator accepted unencodable PDU: %+v", report)
			}
			if report.Complete || len(report.Issues) != 0 {
				t.Fatalf("invalid in-memory state must use existing error path: %+v", report)
			}
		})
	}
	// A real unknown alternative remains opaque and explicitly unchecked.
	unknown := s19.X2APPDU{UnknownExtension: &extension}
	report, err := s20.ValidateMessage(&unknown)
	if err != nil || report.Complete || len(report.Issues) != 0 || len(report.Unchecked) != 1 || report.Unchecked[0].Path != "X2APPDU.unknownExtension" {
		t.Fatalf("valid unknown choice: %+v, %v", report, err)
	}
	wire := listByteapiMust(unknown.MarshalAPER())
	var received s19.X2APPDU
	if _, err := received.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := s20.ValidateMessage(&received); err != nil {
		t.Fatal(err)
	}
	// Received replay state cannot hide a conflicting selector either.
	received.Choice = s00.X2APPDUChoiceInitiatingMessage
	received.InitiatingMessage = &initiating
	if _, err := s20.ValidateMessage(&received); err == nil {
		t.Fatal("received conflicting choice accepted")
	}
	for _, options := range [][]aper.EncodeOption{nil, {aper.WithoutReplay()}} {
		if _, err := received.MarshalAPER(options...); err == nil {
			t.Fatal("received conflicting choice encoded")
		}
	}
}
