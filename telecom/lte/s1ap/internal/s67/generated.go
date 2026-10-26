// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s67 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s67

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s63 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s63"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// NewS1APPDUInitiatingMessage constructs and validates a complete S1AP message.
func NewS1APPDUInitiatingMessage(v s65.InitiatingMessage, options ...aper.BuildOption) (s66.S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	value := s66.BridgeNewS1APPDUInitiatingMessageLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s66.S1APPDU{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1APPDUInitiatingMessage")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s66.S1APPDU{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1APPDUInitiatingMessage")
	}
	if _, err := s66.BridgeS1APPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	return value, aper.OperationError(nil, "S1APPDUInitiatingMessage")
}

// NewS1APPDUSuccessfulOutcome constructs and validates a complete S1AP message.
func NewS1APPDUSuccessfulOutcome(v s64.SuccessfulOutcome, options ...aper.BuildOption) (s66.S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	value := s66.BridgeNewS1APPDUSuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s66.S1APPDU{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1APPDUSuccessfulOutcome")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s66.S1APPDU{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1APPDUSuccessfulOutcome")
	}
	if _, err := s66.BridgeS1APPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "S1APPDUSuccessfulOutcome")
}

// NewS1APPDUUnsuccessfulOutcome constructs and validates a complete S1AP message.
func NewS1APPDUUnsuccessfulOutcome(v s46.UnsuccessfulOutcome, options ...aper.BuildOption) (s66.S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	value := s66.BridgeNewS1APPDUUnsuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s66.S1APPDU{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1APPDUUnsuccessfulOutcome")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s66.S1APPDU{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1APPDUUnsuccessfulOutcome")
	}
	if _, err := s66.BridgeS1APPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s66.S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "S1APPDUUnsuccessfulOutcome")
}
func BridgeValidateInitiatingMessage(v *s65.InitiatingMessage, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitiatingMessage")
	}
	if *s65.BridgeInitiatingValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "InitiatingMessage"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverRequired()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverRequired", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateHandoverRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverRequest", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidateHandoverRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		body, ok := v.Value.AsHandoverNotify()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverNotify", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateHandoverNotifyBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverNotificationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		body, ok := v.Value.AsPathSwitchRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PathSwitchRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidatePathSwitchRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsHandoverCancel()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverCancel", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateHandoverCancelBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsERABSetupRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABSetupRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateERABSetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsERABModifyRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModifyRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateERABModifyRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABModifyProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsERABReleaseCommand()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABReleaseCommand", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateERABReleaseCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		body, ok := v.Value.AsERABReleaseIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABReleaseIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateERABReleaseIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABReleaseIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsInitialContextSetupRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialContextSetupRequest", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidateInitialContextSetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		body, ok := v.Value.AsPaging()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing Paging", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidatePagingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.PagingProcedure().Info().Rule}})
		}
		return report, nil
	case 11:
		body, ok := v.Value.AsDownlinkNASTransport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkNASTransport", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateDownlinkNASTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.DownlinkNASTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 12:
		body, ok := v.Value.AsInitialUEMessage()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialUEMessage", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateInitialUEMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.InitialUEMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 13:
		body, ok := v.Value.AsUplinkNASTransport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkNASTransport", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUplinkNASTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UplinkNASTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 14:
		body, ok := v.Value.AsReset()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing Reset", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateResetBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 15:
		body, ok := v.Value.AsErrorIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ErrorIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateErrorIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ErrorIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 16:
		body, ok := v.Value.AsNASNonDeliveryIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing NASNonDeliveryIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateNASNonDeliveryIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.NASNonDeliveryIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 17:
		body, ok := v.Value.AsS1SetupRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1SetupRequest", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateS1SetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		body, ok := v.Value.AsUEContextReleaseRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextReleaseRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUEContextReleaseRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEContextReleaseRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 19:
		body, ok := v.Value.AsDownlinkS1cdma2000tunnelling()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkS1cdma2000tunnelling", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateDownlinkS1cdma2000tunnellingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.DownlinkS1cdma2000tunnellingProcedure().Info().Rule}})
		}
		return report, nil
	case 20:
		body, ok := v.Value.AsUplinkS1cdma2000tunnelling()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkS1cdma2000tunnelling", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUplinkS1cdma2000tunnellingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UplinkS1cdma2000tunnellingProcedure().Info().Rule}})
		}
		return report, nil
	case 21:
		body, ok := v.Value.AsUEContextModificationRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationRequest", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidateUEContextModificationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		body, ok := v.Value.AsUECapabilityInfoIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UECapabilityInfoIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUECapabilityInfoIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UECapabilityInfoIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 23:
		body, ok := v.Value.AsUEContextReleaseCommand()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextReleaseCommand", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUEContextReleaseCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEContextReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 24:
		body, ok := v.Value.AsENBStatusTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateENBStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 25:
		body, ok := v.Value.AsMMEStatusTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateMMEStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMEStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 26:
		body, ok := v.Value.AsDeactivateTrace()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DeactivateTrace", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateDeactivateTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.DeactivateTraceProcedure().Info().Rule}})
		}
		return report, nil
	case 27:
		body, ok := v.Value.AsTraceStart()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing TraceStart", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidateTraceStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.TraceStartProcedure().Info().Rule}})
		}
		return report, nil
	case 28:
		body, ok := v.Value.AsTraceFailureIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing TraceFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateTraceFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.TraceFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 29:
		body, ok := v.Value.AsENBConfigurationUpdate()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationUpdate", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateENBConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsMMEConfigurationUpdate()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationUpdate", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateMMEConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		body, ok := v.Value.AsLocationReportingControl()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing LocationReportingControl", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateLocationReportingControlBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.LocationReportingControlProcedure().Info().Rule}})
		}
		return report, nil
	case 32:
		body, ok := v.Value.AsLocationReportingFailureIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing LocationReportingFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateLocationReportingFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.LocationReportingFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 33:
		body, ok := v.Value.AsLocationReport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing LocationReport", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateLocationReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.LocationReportProcedure().Info().Rule}})
		}
		return report, nil
	case 34:
		body, ok := v.Value.AsOverloadStart()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OverloadStart", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateOverloadStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.OverloadStartProcedure().Info().Rule}})
		}
		return report, nil
	case 35:
		body, ok := v.Value.AsOverloadStop()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OverloadStop", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateOverloadStopBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.OverloadStopProcedure().Info().Rule}})
		}
		return report, nil
	case 36:
		body, ok := v.Value.AsWriteReplaceWarningRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing WriteReplaceWarningRequest", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidateWriteReplaceWarningRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.WriteReplaceWarningProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		body, ok := v.Value.AsENBDirectInformationTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBDirectInformationTransfer", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateENBDirectInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBDirectInformationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 38:
		body, ok := v.Value.AsMMEDirectInformationTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEDirectInformationTransfer", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateMMEDirectInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMEDirectInformationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 39:
		body, ok := v.Value.AsPrivateMessage()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PrivateMessage", "InitiatingMessage.value:")
		}
		report, err := s58.BridgeValidatePrivateMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.PrivateMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 40:
		body, ok := v.Value.AsENBConfigurationTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationTransfer", "InitiatingMessage.value:")
		}
		report, err := s66.BridgeValidateENBConfigurationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.ENBConfigurationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 41:
		body, ok := v.Value.AsMMEConfigurationTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationTransfer", "InitiatingMessage.value:")
		}
		report, err := s66.BridgeValidateMMEConfigurationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.MMEConfigurationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 42:
		body, ok := v.Value.AsCellTrafficTrace()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing CellTrafficTrace", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateCellTrafficTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.CellTrafficTraceProcedure().Info().Rule}})
		}
		return report, nil
	case 43:
		body, ok := v.Value.AsKillRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing KillRequest", "InitiatingMessage.value:")
		}
		report, err := s64.BridgeValidateKillRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.KillProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		body, ok := v.Value.AsDownlinkUEAssociatedLPPaTransport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.DownlinkUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 45:
		body, ok := v.Value.AsUplinkUEAssociatedLPPaTransport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUplinkUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UplinkUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 46:
		body, ok := v.Value.AsDownlinkNonUEAssociatedLPPaTransport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkNonUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.DownlinkNonUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 47:
		body, ok := v.Value.AsUplinkNonUEAssociatedLPPaTransport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkNonUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UplinkNonUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 48:
		body, ok := v.Value.AsUERadioCapabilityMatchRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityMatchRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUERadioCapabilityMatchRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UERadioCapabilityMatchProcedure().Info().Rule}})
		}
		return report, nil
	case 49:
		body, ok := v.Value.AsPWSRestartIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PWSRestartIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidatePWSRestartIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.PWSRestartIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 50:
		body, ok := v.Value.AsERABModificationIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModificationIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateERABModificationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 51:
		body, ok := v.Value.AsPWSFailureIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PWSFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidatePWSFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.PWSFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 52:
		body, ok := v.Value.AsRerouteNASRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing RerouteNASRequest", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateRerouteNASRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.RerouteNASRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 53:
		body, ok := v.Value.AsUEContextModificationIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUEContextModificationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEContextModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 54:
		body, ok := v.Value.AsConnectionEstablishmentIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ConnectionEstablishmentIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateConnectionEstablishmentIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ConnectionEstablishmentIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 55:
		body, ok := v.Value.AsUEContextSuspendRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextSuspendRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUEContextSuspendRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEContextSuspendProcedure().Info().Rule}})
		}
		return report, nil
	case 56:
		body, ok := v.Value.AsUEContextResumeRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextResumeRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUEContextResumeRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		body, ok := v.Value.AsNASDeliveryIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing NASDeliveryIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateNASDeliveryIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.NASDeliveryIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 58:
		body, ok := v.Value.AsRetrieveUEInformation()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing RetrieveUEInformation", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateRetrieveUEInformationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.RetrieveUEInformationProcedure().Info().Rule}})
		}
		return report, nil
	case 59:
		body, ok := v.Value.AsUEInformationTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEInformationTransfer", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUEInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UEInformationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 60:
		body, ok := v.Value.AsENBCPRelocationIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBCPRelocationIndication", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateENBCPRelocationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBCPRelocationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 61:
		body, ok := v.Value.AsMMECPRelocationIndication()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMECPRelocationIndication", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateMMECPRelocationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMECPRelocationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 62:
		body, ok := v.Value.AsSecondaryRATDataUsageReport()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing SecondaryRATDataUsageReport", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateSecondaryRATDataUsageReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.SecondaryRATDataUsageReportProcedure().Info().Rule}})
		}
		return report, nil
	case 63:
		body, ok := v.Value.AsUERadioCapabilityIDMappingRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityIDMappingRequest", "InitiatingMessage.value:")
		}
		report, err := s63.BridgeValidateUERadioCapabilityIDMappingRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 64:
		body, ok := v.Value.AsHandoverSuccess()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverSuccess", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateHandoverSuccessBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverSuccessProcedure().Info().Rule}})
		}
		return report, nil
	case 65:
		body, ok := v.Value.AsENBEarlyStatusTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBEarlyStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s61.BridgeValidateENBEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBEarlyStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 66:
		body, ok := v.Value.AsMMEEarlyStatusTransfer()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEEarlyStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateMMEEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMEEarlyStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 67:
		body, ok := v.Value.AsS1RemovalRequest()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1RemovalRequest", "InitiatingMessage.value:")
		}
		report, err := s62.BridgeValidateS1RemovalRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s66.S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s25.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "InitiatingMessage.value"})
			return report
		}(), nil
	}
}

// TS 36.413 V19.2.0 §9.3.2 and X.691 (02/2021) §§11.2.1,23 select one complete PDU alternative.
func BridgeValidateMessageBudget(v *s66.S1APPDU, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1APPDU")
	}
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s known choice %d and unknown extension are both selected", "S1APPDU:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s extension index %d must be non-negative", "S1APPDU:", v.UnknownExtension.Index())
		}
		if len(v.UnknownExtension.Contents()) == 0 {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s unknown extension requires a complete encoding", "S1APPDU:")
		}
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "S1APPDU.unknownExtension"})
			return report
		}(), nil
	}
	switch v.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		return BridgeValidateInitiatingMessage(v.InitiatingMessage, budget)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		return s66.BridgeValidateSuccessfulOutcome(v.SuccessfulOutcome, budget)
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		return s66.BridgeValidateUnsuccessfulOutcome(v.UnsuccessfulOutcome, budget)
	default:
		if v.UnknownExtension != nil {
			if len(v.UnknownExtension.Contents()) == 0 {
				return func() s25.ValidationReport {
					sealed := s25.ValidationReport{}
					*s25.BridgeValidationReportFieldBudget(&sealed) = budget
					return sealed
				}(), fmt.Errorf("%s unknown extension has empty complete encoding", "S1APPDU:")
			}
			return func() s25.ValidationReport {
				report := func() s25.ValidationReport {
					sealed := s25.ValidationReport{Complete: false}
					*s25.BridgeValidationReportFieldBudget(&sealed) = budget
					return sealed
				}()
				s25.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "S1APPDU.unknownExtension"})
				return report
			}(), nil
		}
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("%s invalid choice %d", "S1APPDU:", v.Choice)
	}
}
func ValidateMessage(v *s66.S1APPDU, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "Message")
	}
	report, err := BridgeValidateMessageBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s66.BridgeS1APPDUMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Message")
}
