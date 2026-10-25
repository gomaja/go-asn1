// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// Build validates the body and constructs the bound procedure message.
func (b ErrorIndicationUnsuccessfulBinding) Build(body s20.ErrorIndication, options ...aper.BuildOption) (s14.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s14.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
