// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s63 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s63"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	s67 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s67"
	testing "testing"
)

// TS 36.413 V19.2.0 §§9.3.0,9.3.3 and 10.3.1–10.3.6 define these
// independently varied sender structure cases.
func TestValidationAndBuildersRefuseEachIssue(t *testing.T) {
	table := s27.S1SetupFailureIEs()
	cause := causeFreshMust(s30.NewCauseMisc(s00.CauseMiscUnspecified))
	field := s1SetupFailureIEFieldFreshMust(table.Cause().New(cause))
	wait := s1SetupFailureIEFieldFreshMust(table.TimeToWait().New(s00.TimeToWaitV1s))
	unknown := s1SetupFailureIEFieldFreshMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	disallowed := s1SetupFailureIEFieldFreshMust(table.NewOpaque(0, s00.CriticalityIgnore, []byte{0}))
	wrong := field
	wrong.Criticality = s00.CriticalityReject
	cases := []struct {
		name   string
		fields s27.S1SetupFailureIEContainer
		code   s00.ValidationCode
		id     s00.ProtocolIEID
		clause string
	}{
		{"missing", nil, s00.MissingMandatory, 2, "§10.3.5"},
		{"not allowed", s27.S1SetupFailureIEContainer{field, disallowed}, s00.NotAllowed, 0, "§10.3.1"},
		{"criticality", s27.S1SetupFailureIEContainer{wrong}, s00.WrongCriticality, 2, "§10.3.2"},
		{"repeated", s27.S1SetupFailureIEContainer{field, field}, s00.RepeatedIE, 2, "§10.3.6"},
		{"order", s27.S1SetupFailureIEContainer{wait, unknown, field}, s00.WrongOrder, 2, "§10.3.6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := s31.S1SetupFailure{ProtocolIEs: tc.fields}
			message := s46.UnsuccessfulOutcome{ProcedureCode: 17, Criticality: s00.CriticalityReject, Value: func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = 17
				*s46.BridgeUnsuccessfulValueFieldBodyS1SetupFailure(&sealed) = &body
				return sealed
			}()}
			pdu := s66.S1APPDU{Choice: s00.S1APPDUChoiceUnsuccessfulOutcome, UnsuccessfulOutcome: &message}
			report, err := s67.ValidateMessage(&pdu)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, issue := range report.Issues {
				if issue.Code == tc.code && issue.IEID == tc.id && issue.Severity == s00.ValidationSeverityError {
					found = true
					if issue.Location.Path == "" || !issue.HasIEID || issue.Rule.Document != "3GPP TS 36.413" {
						t.Fatalf("incomplete issue: %+v", issue)
					}
					clause := issue.Rule.Clause == tc.clause
					for _, rule := range issue.RelatedRules {
						clause = clause || rule.Document == "3GPP TS 36.413" && rule.Clause == tc.clause
					}
					if !clause {
						t.Errorf("wrong clause: %+v", issue)
					}
				}
			}
			if !found {
				t.Fatalf("missing %v for %d: %+v", tc.code, tc.id, report.Issues)
			}
			var build *s25.BuildError
			if _, err := s62.NewS1SetupFailure(tc.fields); !errors.As(err, &build) {
				t.Fatalf("body builder=%v", err)
			}
			if _, err := s66.S1SetupProcedure().Unsuccessful().Build(body); !errors.As(err, &build) {
				t.Fatalf("procedure builder=%v", err)
			}
			wire, err := pdu.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var decoded s66.S1APPDU
			if _, err := decoded.UnmarshalAPER(wire); err != nil {
				t.Fatalf("structure must remain decodable: %v", err)
			}
		})
	}
	valid := s27.S1SetupFailureIEContainer{field, unknown, wait}
	if _, err := s62.NewS1SetupFailure(valid); err != nil {
		t.Fatalf("unknown IE changed source order: %v", err)
	}
	// Conditional source rows are deferred without inventing their context.
	report, err := s63.ValidateHandoverRequired(&s43.HandoverRequired{})
	if err != nil || len(report.Deferred) == 0 || report.Complete {
		t.Fatalf("conditional report=%+v err=%v", report, err)
	}
	// A source-known extension in an unrelated empty table is an error.
	for _, id := range []s00.ProtocolExtensionID{317, 65532} {
		ext := criticalityDiagnosticsExtIEsExtFieldFreshMust(s09.CriticalityDiagnosticsExtIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0}))
		diag := s26.CriticalityDiagnostics{IEExtensions: s09.CriticalityDiagnosticsExtIEsExtContainer{ext}}
		outer := errorIndicationIEFieldFreshMust(s36.ErrorIndicationIEs().CriticalityDiagnostics().New(diag))
		fields := s36.ErrorIndicationIEContainer{outer}
		_, err := s62.NewErrorIndication(fields)
		if id == 317 {
			var build *s25.BuildError
			if !errors.As(err, &build) {
				t.Fatalf("known extension accepted: %v", err)
			}
		} else if err != nil {
			t.Fatalf("future extension refused: %v", err)
		}
	}
	// The opaque constructors cannot bypass any known schema selector.
	if _, err := table.NewOpaque(2, s00.CriticalityIgnore, []byte{0}); err == nil {
		t.Fatal("known IE became opaque")
	}
	if _, err := s37.ERABInformationListItemExtIEs().NewOpaque(317, s00.CriticalityIgnore, []byte{0}); err == nil {
		t.Fatal("known extension became opaque")
	}
	if _, err := s46.NewOpaqueUnsuccessfulOutcome(17, s00.CriticalityReject, []byte{0}); err == nil {
		t.Fatal("known outcome became opaque")
	}
	for _, index := range []uint64{0, 1} {
		if _, err := s23.NewENBIDUnknownExtension(index, []byte{0}); err == nil {
			t.Fatalf("known CHOICE addition %d became opaque", index)
		}
	}
	if _, err := s67.ValidateMessage(nil); err == nil {
		t.Fatal("nil validation root accepted")
	}
}
