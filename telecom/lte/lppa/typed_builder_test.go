package lppa

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	"testing"
)

func TestECIDMeasurementInitiationRequestBuilderRejectsStructure(t *testing.T) {
	base := ECIDMeasurementInitiationRequestIEContainer{
		{Id: 2, Criticality: CriticalityReject},
		{Id: 3, Criticality: CriticalityReject},
		{Id: 5, Criticality: CriticalityReject},
	}
	cases := []struct {
		name   string
		fields ECIDMeasurementInitiationRequestIEContainer
		code   ValidationCode
	}{
		{"missing mandatory", base[:2], MissingMandatory},
		{"not allowed", append(append(ECIDMeasurementInitiationRequestIEContainer{}, base...), ECIDMeasurementInitiationRequestIEField{Id: 6}), NotAllowed},
		{"duplicate", append(append(ECIDMeasurementInitiationRequestIEContainer{}, base...), base[0]), RepeatedIE},
		{"wrong criticality", ECIDMeasurementInitiationRequestIEContainer{{Id: 2, Criticality: CriticalityIgnore}, base[1], base[2]}, WrongCriticality},
		{"wrong order", ECIDMeasurementInitiationRequestIEContainer{base[1], base[0], base[2]}, WrongOrder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewECIDMeasurementInitiationRequest(tc.fields)
			var buildErr *BuildError
			if !errors.As(err, &buildErr) {
				t.Fatalf("error = %v, want BuildError", err)
			}
			found := false
			for _, issue := range buildErr.Issues {
				if issue.Code == tc.code && issue.Location.Path != "" {
					found = true
				}
			}
			if !found {
				t.Errorf("missing %v issue: %+v", tc.code, buildErr.Issues)
			}
		})
	}
}
func TestLPPAPDUChoiceConstructorRejectsInvalidBody(t *testing.T) {
	body := ECIDMeasurementInitiationRequest{}
	message := InitiatingMessage{ProcedureCode: 2, Criticality: CriticalityReject, LppatransactionID: 7, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*s21.BridgeInitiatingValueFieldCode(&sealed) = 2
		*s21.BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(&sealed) = &body
		return sealed
	}()}
	_, err := NewLPPAPDUInitiatingMessage(message)
	var buildErr *BuildError
	if !errors.As(err, &buildErr) || len(buildErr.Issues) == 0 || buildErr.Issues[0].Code != MissingMandatory {
		t.Fatalf("constructor error = %v", err)
	}
}
