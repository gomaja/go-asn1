package lppa

import (
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	"testing"
)

func TestValidateMessageReportsEachStructuralIssue(t *testing.T) {
	base := ECIDMeasurementInitiationRequestIEContainer{
		{Id: 2, Criticality: CriticalityReject},
		{Id: 3, Criticality: CriticalityReject},
		{Id: 5, Criticality: CriticalityReject},
	}
	cases := []struct {
		name   string
		fields ECIDMeasurementInitiationRequestIEContainer
		want   ValidationCode
	}{
		{"missing", base[:2], MissingMandatory},
		{"not allowed", append(append(ECIDMeasurementInitiationRequestIEContainer{}, base...), ECIDMeasurementInitiationRequestIEField{Id: 6, Criticality: CriticalityReject}), NotAllowed},
		{"wrong criticality", ECIDMeasurementInitiationRequestIEContainer{{Id: 2, Criticality: CriticalityIgnore}, base[1], base[2]}, WrongCriticality},
		{"repeated", ECIDMeasurementInitiationRequestIEContainer{base[0], base[1], base[2], base[2]}, RepeatedIE},
		{"wrong order", ECIDMeasurementInitiationRequestIEContainer{base[1], base[0], base[2]}, WrongOrder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := ECIDMeasurementInitiationRequest{ProtocolIEs: tc.fields}
			message := InitiatingMessage{ProcedureCode: 2, Criticality: CriticalityReject, LppatransactionID: 7, Value: func() InitiatingValue {
				sealed := InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = 2
				*s21.BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(&sealed) = &body
				return sealed
			}()}
			pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &message}
			report, err := ValidateMessage(&pdu)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, issue := range report.Issues {
				if issue.Code != tc.want {
					continue
				}
				found = true
				if issue.Location.Path == "" || issue.Rule.Document != "3GPP TS 36.455" || issue.Rule.Clause != "§10" || !issue.HasIEID {
					t.Fatalf("issue lacks location, IE or clause: %+v", issue)
				}
			}
			if !found {
				t.Fatalf("missing issue %v: %+v", tc.want, report.Issues)
			}
		})
	}
}
func TestValidateECIDMeasurementInitiationRequestStructure(t *testing.T) {
	request := ECIDMeasurementInitiationRequest{ProtocolIEs: ECIDMeasurementInitiationRequestIEContainer{
		{Id: 3, Criticality: CriticalityReject},
		{Id: 2, Criticality: CriticalityIgnore},
		{Id: 2, Criticality: CriticalityReject},
		{Id: 6, Criticality: CriticalityReject},
	}}
	report, err := ValidateECIDMeasurementInitiationRequest(&request)
	if err != nil {
		t.Fatal(err)
	}
	want := map[ValidationCode]ProtocolIEID{MissingMandatory: 5, NotAllowed: 6, WrongCriticality: 2, RepeatedIE: 2, WrongOrder: 2}
	for code, id := range want {
		found := false
		for _, issue := range report.Issues {
			if issue.Code == code && issue.IEID == id {
				found = true
				if issue.Rule.Document != "3GPP TS 36.455" || issue.Rule.Clause == "" {
					t.Errorf("issue %v has no TS 36.455 clause: %+v", code, issue.Rule)
				}
				if issue.Location.Path == "" {
					t.Errorf("issue %v has no path", code)
				}
			}
		}
		if !found {
			t.Errorf("missing issue %v for IE %d: %+v", code, id, report.Issues)
		}
	}
}
