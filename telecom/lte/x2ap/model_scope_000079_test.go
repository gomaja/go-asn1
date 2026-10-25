// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	testing "testing"
)

func TestValidationHandlingProvenance(t *testing.T) {
	field, err := s11.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	body := s20.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{field}}
	report, err := s20.ValidateErrorIndication(&body)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	issue := report.Issues[0]
	if issue.Code != s00.NotAllowed || issue.Severity != s00.ValidationSeverityUnrecognized || len(issue.RelatedRules) != 2 || issue.RelatedRules[0].Clause != "§10.3.1" || issue.RelatedRules[1].Clause != "§10.3.4.2" {
		t.Fatalf("handling: %+v", issue)
	}
	message, err := s19.NewOpaqueSuccessfulOutcome(3, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	pdu := s20.X2APPDU{Choice: s00.X2APPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &message}
	report, err = s21.ValidateMessage(&pdu)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("outcome report=%+v err=%v", report, err)
	}
	issue = report.Issues[0]
	if issue.Code != s00.UnavailableOutcome || len(issue.RelatedRules) != 2 || issue.RelatedRules[0].Clause != "§10.3.4.1" || issue.RelatedRules[1].Clause != "§10.3.4.1A" {
		t.Fatalf("outcome handling: %+v", issue)
	}
}
