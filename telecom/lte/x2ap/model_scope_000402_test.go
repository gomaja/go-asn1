// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// Build validates the body and constructs the bound procedure message.
func (b ErrorIndicationSuccessfulBinding) Build(body s19.ErrorIndication, options ...aper.BuildOption) (s18.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s18.SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s18.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
