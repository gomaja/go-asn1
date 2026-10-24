// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

// TS 36.423 V19.1.0 §§9.3.1, 9.3.4 and §10: decoding retains
// structurally readable messages; checked construction reports their errors.
func TestTypedStructuralValidation(t *testing.T) {
	table := s11.ErrorIndicationIEs()
	cause := errorIndicationIEFieldapiMust(table.Cause().New(apiCause()))
	diagnostics := errorIndicationIEFieldapiMust(table.CriticalityDiagnostics().New(s06.CriticalityDiagnostics{}))
	for _, tc := range []struct {
		name   string
		fields s11.ErrorIndicationIEContainer
		code   s00.ValidationCode
	}{
		{"unknown repeated", s11.ErrorIndicationIEContainer{errorIndicationIEFieldapiMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0})), errorIndicationIEFieldapiMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))}, s00.RepeatedIE},
		{"repeated", s11.ErrorIndicationIEContainer{cause, cause}, s00.RepeatedIE},
		{"order", s11.ErrorIndicationIEContainer{diagnostics, cause}, s00.WrongOrder},
		{"criticality", s11.ErrorIndicationIEContainer{func() s11.ErrorIndicationIEField {
			v := cause
			v.Criticality = s00.CriticalityReject
			return v
		}()}, s00.WrongCriticality},
		{"not allowed", s11.ErrorIndicationIEContainer{errorIndicationIEFieldapiMust(table.NewOpaque(405, s00.CriticalityIgnore, []byte{0}))}, s00.NotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := s19.ErrorIndication{ProtocolIEs: tc.fields}
			report, err := s19.ValidateErrorIndication(&body)
			if err != nil {
				t.Fatal(err)
			}
			apiHas(t, report, tc.code)
			_, err = s19.NewErrorIndication(tc.fields)
			var build *s12.BuildError
			if !errors.As(err, &build) {
				t.Fatalf("builder accepted invalid message: %v", err)
			}
			wire, err := body.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var received s19.ErrorIndication
			if _, err = received.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			again, err := received.MarshalAPER()
			if err != nil || !bytes.Equal(wire, again) {
				t.Fatal("structural violation did not replay")
			}
		})
	}
	missing := s14.X2SetupFailure{}
	report, err := s14.ValidateX2SetupFailure(&missing)
	if err != nil {
		t.Fatal(err)
	}
	apiHas(t, report, s00.MissingMandatory)
	if _, err := s14.NewX2SetupFailure(nil); err == nil {
		t.Fatal("builder invented missing mandatory IE")
	}
	unknown := errorIndicationIEFieldapiMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	body := s19.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{cause, unknown, diagnostics}}
	report, err = s19.ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range report.Issues {
		if issue.Code == s00.WrongOrder || issue.Severity == s00.ValidationSeverityError {
			t.Errorf("unknown affected order: %+v", issue)
		}
	}
	if _, err := s19.NewErrorIndication(body.ProtocolIEs); err != nil {
		t.Fatal(err)
	}
	// A known extension ID is known even when absent from this empty extension table.
	cd := s06.CriticalityDiagnostics{IEExtensions: s02.CriticalityDiagnosticsExtIEsExtContainer{criticalityDiagnosticsExtIEsExtFieldapiMust(s06.CriticalityDiagnosticsExtIEs().NewOpaque(405, s00.CriticalityIgnore, []byte{0}))}}
	report = s12.ValidationReport{Complete: true}
	s13.X2apInternalWalkValidationCriticalityDiagnostics(&cd, &report, "CriticalityDiagnostics", false)
	apiHas(t, report, s00.NotAllowed)
}
