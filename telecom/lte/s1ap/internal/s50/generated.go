// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s50 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s50

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewHandoverRequired(fields s34.HandoverRequiredIEContainer, options ...aper.BuildOption) (s35.HandoverRequired, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s34.HandoverRequiredIEField](bb, uint64(len(fields))); err != nil {
		return s35.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	v := s35.HandoverRequired{ProtocolIEs: make(s34.HandoverRequiredIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequiredBudget(&v, budget)
	if err != nil {
		return s35.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s35.HandoverRequired{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverRequired")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s35.HandoverRequired{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverRequired")
	}
	if _, err := s35.BridgeHandoverRequiredMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s35.HandoverRequired{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequired.protocolIEs:", err), "HandoverRequired")
	}
	return v, aper.OperationError(nil, "HandoverRequired")
}
func NewHandoverCommand(fields s41.HandoverCommandIEContainer, options ...aper.BuildOption) (s41.HandoverCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s41.HandoverCommand{}, aper.OperationError(err, "HandoverCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.HandoverCommandIEField](bb, uint64(len(fields))); err != nil {
		return s41.HandoverCommand{}, aper.OperationError(err, "HandoverCommand")
	}
	v := s41.HandoverCommand{ProtocolIEs: make(s41.HandoverCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverCommandBudget(&v, budget)
	if err != nil {
		return s41.HandoverCommand{}, aper.OperationError(err, "HandoverCommand")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s41.HandoverCommand{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverCommand")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s41.HandoverCommand{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverCommand")
	}
	if _, err := s41.BridgeHandoverCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s41.HandoverCommand{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverCommand.protocolIEs:", err), "HandoverCommand")
	}
	return v, aper.OperationError(nil, "HandoverCommand")
}
func NewHandoverPreparationFailure(fields s22.HandoverPreparationFailureIEContainer, options ...aper.BuildOption) (s25.HandoverPreparationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.HandoverPreparationFailure{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.HandoverPreparationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s25.HandoverPreparationFailure{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	v := s25.HandoverPreparationFailure{ProtocolIEs: make(s22.HandoverPreparationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverPreparationFailureBudget(&v, budget)
	if err != nil {
		return s25.HandoverPreparationFailure{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.HandoverPreparationFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverPreparationFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.HandoverPreparationFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverPreparationFailure")
	}
	if _, err := s25.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.HandoverPreparationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverPreparationFailure.protocolIEs:", err), "HandoverPreparationFailure")
	}
	return v, aper.OperationError(nil, "HandoverPreparationFailure")
}
func NewHandoverRequestAcknowledge(fields s39.HandoverRequestAcknowledgeIEContainer, options ...aper.BuildOption) (s39.HandoverRequestAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s39.HandoverRequestAcknowledge{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.HandoverRequestAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s39.HandoverRequestAcknowledge{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	v := s39.HandoverRequestAcknowledge{ProtocolIEs: make(s39.HandoverRequestAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequestAcknowledgeBudget(&v, budget)
	if err != nil {
		return s39.HandoverRequestAcknowledge{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s39.HandoverRequestAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverRequestAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s39.HandoverRequestAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverRequestAcknowledge")
	}
	if _, err := s39.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s39.HandoverRequestAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequestAcknowledge.protocolIEs:", err), "HandoverRequestAcknowledge")
	}
	return v, aper.OperationError(nil, "HandoverRequestAcknowledge")
}
func NewHandoverFailure(fields s22.HandoverFailureIEContainer, options ...aper.BuildOption) (s25.HandoverFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.HandoverFailure{}, aper.OperationError(err, "HandoverFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.HandoverFailureIEField](bb, uint64(len(fields))); err != nil {
		return s25.HandoverFailure{}, aper.OperationError(err, "HandoverFailure")
	}
	v := s25.HandoverFailure{ProtocolIEs: make(s22.HandoverFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverFailureBudget(&v, budget)
	if err != nil {
		return s25.HandoverFailure{}, aper.OperationError(err, "HandoverFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.HandoverFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.HandoverFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverFailure")
	}
	if _, err := s25.BridgeHandoverFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.HandoverFailure{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverFailure.protocolIEs:", err), "HandoverFailure")
	}
	return v, aper.OperationError(nil, "HandoverFailure")
}
func NewHandoverNotify(fields s35.HandoverNotifyIEContainer, options ...aper.BuildOption) (s36.HandoverNotify, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s35.HandoverNotifyIEField](bb, uint64(len(fields))); err != nil {
		return s36.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	v := s36.HandoverNotify{ProtocolIEs: make(s35.HandoverNotifyIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverNotifyBudget(&v, budget)
	if err != nil {
		return s36.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.HandoverNotify{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverNotify")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.HandoverNotify{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverNotify")
	}
	if _, err := s36.BridgeHandoverNotifyMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.HandoverNotify{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverNotify.protocolIEs:", err), "HandoverNotify")
	}
	return v, aper.OperationError(nil, "HandoverNotify")
}
func NewPathSwitchRequestFailure(fields s23.PathSwitchRequestFailureIEContainer, options ...aper.BuildOption) (s26.PathSwitchRequestFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s26.PathSwitchRequestFailure{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.PathSwitchRequestFailureIEField](bb, uint64(len(fields))); err != nil {
		return s26.PathSwitchRequestFailure{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	v := s26.PathSwitchRequestFailure{ProtocolIEs: make(s23.PathSwitchRequestFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestFailureBudget(&v, budget)
	if err != nil {
		return s26.PathSwitchRequestFailure{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s26.PathSwitchRequestFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PathSwitchRequestFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s26.PathSwitchRequestFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PathSwitchRequestFailure")
	}
	if _, err := s26.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s26.PathSwitchRequestFailure{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequestFailure.protocolIEs:", err), "PathSwitchRequestFailure")
	}
	return v, aper.OperationError(nil, "PathSwitchRequestFailure")
}
func NewHandoverCancel(fields s18.HandoverCancelIEContainer, options ...aper.BuildOption) (s25.HandoverCancel, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.HandoverCancel{}, aper.OperationError(err, "HandoverCancel")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s18.HandoverCancelIEField](bb, uint64(len(fields))); err != nil {
		return s25.HandoverCancel{}, aper.OperationError(err, "HandoverCancel")
	}
	v := s25.HandoverCancel{ProtocolIEs: make(s18.HandoverCancelIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverCancelBudget(&v, budget)
	if err != nil {
		return s25.HandoverCancel{}, aper.OperationError(err, "HandoverCancel")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.HandoverCancel{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverCancel")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.HandoverCancel{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverCancel")
	}
	if _, err := s25.BridgeHandoverCancelMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.HandoverCancel{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverCancel.protocolIEs:", err), "HandoverCancel")
	}
	return v, aper.OperationError(nil, "HandoverCancel")
}
func NewHandoverCancelAcknowledge(fields s22.HandoverCancelAcknowledgeIEContainer, options ...aper.BuildOption) (s25.HandoverCancelAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.HandoverCancelAcknowledge{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.HandoverCancelAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s25.HandoverCancelAcknowledge{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	v := s25.HandoverCancelAcknowledge{ProtocolIEs: make(s22.HandoverCancelAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverCancelAcknowledgeBudget(&v, budget)
	if err != nil {
		return s25.HandoverCancelAcknowledge{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.HandoverCancelAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverCancelAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.HandoverCancelAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverCancelAcknowledge")
	}
	if _, err := s25.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.HandoverCancelAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverCancelAcknowledge.protocolIEs:", err), "HandoverCancelAcknowledge")
	}
	return v, aper.OperationError(nil, "HandoverCancelAcknowledge")
}
func NewERABSetupRequest(fields s41.ERABSetupRequestIEContainer, options ...aper.BuildOption) (s41.ERABSetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s41.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.ERABSetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s41.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	v := s41.ERABSetupRequest{ProtocolIEs: make(s41.ERABSetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABSetupRequestBudget(&v, budget)
	if err != nil {
		return s41.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s41.ERABSetupRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABSetupRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s41.ERABSetupRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABSetupRequest")
	}
	if _, err := s41.BridgeERABSetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s41.ERABSetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ERABSetupRequest.protocolIEs:", err), "ERABSetupRequest")
	}
	return v, aper.OperationError(nil, "ERABSetupRequest")
}
func NewERABModifyRequest(fields s41.ERABModifyRequestIEContainer, options ...aper.BuildOption) (s41.ERABModifyRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s41.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.ERABModifyRequestIEField](bb, uint64(len(fields))); err != nil {
		return s41.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	v := s41.ERABModifyRequest{ProtocolIEs: make(s41.ERABModifyRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModifyRequestBudget(&v, budget)
	if err != nil {
		return s41.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s41.ERABModifyRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABModifyRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s41.ERABModifyRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABModifyRequest")
	}
	if _, err := s41.BridgeERABModifyRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s41.ERABModifyRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModifyRequest.protocolIEs:", err), "ERABModifyRequest")
	}
	return v, aper.OperationError(nil, "ERABModifyRequest")
}
func NewERABReleaseCommand(fields s40.ERABReleaseCommandIEContainer, options ...aper.BuildOption) (s40.ERABReleaseCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s40.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.ERABReleaseCommandIEField](bb, uint64(len(fields))); err != nil {
		return s40.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	v := s40.ERABReleaseCommand{ProtocolIEs: make(s40.ERABReleaseCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseCommandBudget(&v, budget)
	if err != nil {
		return s40.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s40.ERABReleaseCommand{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABReleaseCommand")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s40.ERABReleaseCommand{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABReleaseCommand")
	}
	if _, err := s40.BridgeERABReleaseCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s40.ERABReleaseCommand{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseCommand.protocolIEs:", err), "ERABReleaseCommand")
	}
	return v, aper.OperationError(nil, "ERABReleaseCommand")
}
func NewInitialContextSetupResponse(fields s40.InitialContextSetupResponseIEContainer, options ...aper.BuildOption) (s40.InitialContextSetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s40.InitialContextSetupResponse{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.InitialContextSetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s40.InitialContextSetupResponse{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	v := s40.InitialContextSetupResponse{ProtocolIEs: make(s40.InitialContextSetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialContextSetupResponseBudget(&v, budget)
	if err != nil {
		return s40.InitialContextSetupResponse{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s40.InitialContextSetupResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "InitialContextSetupResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s40.InitialContextSetupResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "InitialContextSetupResponse")
	}
	if _, err := s40.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s40.InitialContextSetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "InitialContextSetupResponse.protocolIEs:", err), "InitialContextSetupResponse")
	}
	return v, aper.OperationError(nil, "InitialContextSetupResponse")
}
func NewInitialContextSetupFailure(fields s23.InitialContextSetupFailureIEContainer, options ...aper.BuildOption) (s25.InitialContextSetupFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.InitialContextSetupFailure{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.InitialContextSetupFailureIEField](bb, uint64(len(fields))); err != nil {
		return s25.InitialContextSetupFailure{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	v := s25.InitialContextSetupFailure{ProtocolIEs: make(s23.InitialContextSetupFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialContextSetupFailureBudget(&v, budget)
	if err != nil {
		return s25.InitialContextSetupFailure{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.InitialContextSetupFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "InitialContextSetupFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.InitialContextSetupFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "InitialContextSetupFailure")
	}
	if _, err := s25.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.InitialContextSetupFailure{}, aper.OperationError(fmt.Errorf("%s %w", "InitialContextSetupFailure.protocolIEs:", err), "InitialContextSetupFailure")
	}
	return v, aper.OperationError(nil, "InitialContextSetupFailure")
}
func NewDownlinkNASTransport(fields s43.DownlinkNASTransportIEContainer, options ...aper.BuildOption) (s43.DownlinkNASTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.DownlinkNASTransportIEField](bb, uint64(len(fields))); err != nil {
		return s43.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	v := s43.DownlinkNASTransport{ProtocolIEs: make(s43.DownlinkNASTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkNASTransportBudget(&v, budget)
	if err != nil {
		return s43.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s43.DownlinkNASTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "DownlinkNASTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.DownlinkNASTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "DownlinkNASTransport")
	}
	if _, err := s43.BridgeDownlinkNASTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.DownlinkNASTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkNASTransport.protocolIEs:", err), "DownlinkNASTransport")
	}
	return v, aper.OperationError(nil, "DownlinkNASTransport")
}
func NewInitialUEMessage(fields s35.InitialUEMessageIEContainer, options ...aper.BuildOption) (s36.InitialUEMessage, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s35.InitialUEMessageIEField](bb, uint64(len(fields))); err != nil {
		return s36.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	v := s36.InitialUEMessage{ProtocolIEs: make(s35.InitialUEMessageIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialUEMessageBudget(&v, budget)
	if err != nil {
		return s36.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.InitialUEMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "InitialUEMessage")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.InitialUEMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "InitialUEMessage")
	}
	if _, err := s36.BridgeInitialUEMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.InitialUEMessage{}, aper.OperationError(fmt.Errorf("%s %w", "InitialUEMessage.protocolIEs:", err), "InitialUEMessage")
	}
	return v, aper.OperationError(nil, "InitialUEMessage")
}
func NewErrorIndication(fields s28.ErrorIndicationIEContainer, options ...aper.BuildOption) (s28.ErrorIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.ErrorIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s28.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	v := s28.ErrorIndication{ProtocolIEs: make(s28.ErrorIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateErrorIndicationBudget(&v, budget)
	if err != nil {
		return s28.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s28.ErrorIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ErrorIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s28.ErrorIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ErrorIndication")
	}
	if _, err := s28.BridgeErrorIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s28.ErrorIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ErrorIndication.protocolIEs:", err), "ErrorIndication")
	}
	return v, aper.OperationError(nil, "ErrorIndication")
}
func NewNASNonDeliveryIndication(fields s19.NASNonDeliveryIndicationIEContainer, options ...aper.BuildOption) (s26.NASNonDeliveryIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s26.NASNonDeliveryIndication{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s19.NASNonDeliveryIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s26.NASNonDeliveryIndication{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	v := s26.NASNonDeliveryIndication{ProtocolIEs: make(s19.NASNonDeliveryIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateNASNonDeliveryIndicationBudget(&v, budget)
	if err != nil {
		return s26.NASNonDeliveryIndication{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s26.NASNonDeliveryIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "NASNonDeliveryIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s26.NASNonDeliveryIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "NASNonDeliveryIndication")
	}
	if _, err := s26.BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s26.NASNonDeliveryIndication{}, aper.OperationError(fmt.Errorf("%s %w", "NASNonDeliveryIndication.protocolIEs:", err), "NASNonDeliveryIndication")
	}
	return v, aper.OperationError(nil, "NASNonDeliveryIndication")
}
func NewS1SetupRequest(fields s44.S1SetupRequestIEContainer, options ...aper.BuildOption) (s44.S1SetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.S1SetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	v := s44.S1SetupRequest{ProtocolIEs: make(s44.S1SetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupRequestBudget(&v, budget)
	if err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.S1SetupRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1SetupRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.S1SetupRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1SetupRequest")
	}
	if _, err := s44.BridgeS1SetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupRequest.protocolIEs:", err), "S1SetupRequest")
	}
	return v, aper.OperationError(nil, "S1SetupRequest")
}
func NewS1SetupResponse(fields s44.S1SetupResponseIEContainer, options ...aper.BuildOption) (s44.S1SetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.S1SetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s44.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	v := s44.S1SetupResponse{ProtocolIEs: make(s44.S1SetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupResponseBudget(&v, budget)
	if err != nil {
		return s44.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.S1SetupResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1SetupResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.S1SetupResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1SetupResponse")
	}
	if _, err := s44.BridgeS1SetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.S1SetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupResponse.protocolIEs:", err), "S1SetupResponse")
	}
	return v, aper.OperationError(nil, "S1SetupResponse")
}
func NewS1SetupFailure(fields s23.S1SetupFailureIEContainer, options ...aper.BuildOption) (s27.S1SetupFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s27.S1SetupFailure{}, aper.OperationError(err, "S1SetupFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.S1SetupFailureIEField](bb, uint64(len(fields))); err != nil {
		return s27.S1SetupFailure{}, aper.OperationError(err, "S1SetupFailure")
	}
	v := s27.S1SetupFailure{ProtocolIEs: make(s23.S1SetupFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupFailureBudget(&v, budget)
	if err != nil {
		return s27.S1SetupFailure{}, aper.OperationError(err, "S1SetupFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s27.S1SetupFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1SetupFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s27.S1SetupFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1SetupFailure")
	}
	if _, err := s27.BridgeS1SetupFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s27.S1SetupFailure{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupFailure.protocolIEs:", err), "S1SetupFailure")
	}
	return v, aper.OperationError(nil, "S1SetupFailure")
}
func NewDownlinkS1cdma2000tunnelling(fields s40.DownlinkS1cdma2000tunnellingIEContainer, options ...aper.BuildOption) (s41.DownlinkS1cdma2000tunnelling, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s41.DownlinkS1cdma2000tunnelling{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.DownlinkS1cdma2000tunnellingIEField](bb, uint64(len(fields))); err != nil {
		return s41.DownlinkS1cdma2000tunnelling{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	v := s41.DownlinkS1cdma2000tunnelling{ProtocolIEs: make(s40.DownlinkS1cdma2000tunnellingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkS1cdma2000tunnellingBudget(&v, budget)
	if err != nil {
		return s41.DownlinkS1cdma2000tunnelling{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s41.DownlinkS1cdma2000tunnelling{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "DownlinkS1cdma2000tunnelling")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s41.DownlinkS1cdma2000tunnelling{}, aper.OperationError(&s21.BuildError{Issues: issues}, "DownlinkS1cdma2000tunnelling")
	}
	if _, err := s41.BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s41.DownlinkS1cdma2000tunnelling{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkS1cdma2000tunnelling.protocolIEs:", err), "DownlinkS1cdma2000tunnelling")
	}
	return v, aper.OperationError(nil, "DownlinkS1cdma2000tunnelling")
}
func NewENBStatusTransfer(fields s22.ENBStatusTransferIEContainer, options ...aper.BuildOption) (s24.ENBStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.ENBStatusTransfer{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.ENBStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s24.ENBStatusTransfer{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	v := s24.ENBStatusTransfer{ProtocolIEs: make(s22.ENBStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBStatusTransferBudget(&v, budget)
	if err != nil {
		return s24.ENBStatusTransfer{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s24.ENBStatusTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBStatusTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s24.ENBStatusTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBStatusTransfer")
	}
	if _, err := s24.BridgeENBStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s24.ENBStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBStatusTransfer.protocolIEs:", err), "ENBStatusTransfer")
	}
	return v, aper.OperationError(nil, "ENBStatusTransfer")
}
func NewMMEStatusTransfer(fields s22.MMEStatusTransferIEContainer, options ...aper.BuildOption) (s26.MMEStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s26.MMEStatusTransfer{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.MMEStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s26.MMEStatusTransfer{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	v := s26.MMEStatusTransfer{ProtocolIEs: make(s22.MMEStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEStatusTransferBudget(&v, budget)
	if err != nil {
		return s26.MMEStatusTransfer{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s26.MMEStatusTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEStatusTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s26.MMEStatusTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEStatusTransfer")
	}
	if _, err := s26.BridgeMMEStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s26.MMEStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEStatusTransfer.protocolIEs:", err), "MMEStatusTransfer")
	}
	return v, aper.OperationError(nil, "MMEStatusTransfer")
}
func NewDeactivateTrace(fields s08.DeactivateTraceIEContainer, options ...aper.BuildOption) (s15.DeactivateTrace, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DeactivateTrace{}, aper.OperationError(err, "DeactivateTrace")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s08.DeactivateTraceIEField](bb, uint64(len(fields))); err != nil {
		return s15.DeactivateTrace{}, aper.OperationError(err, "DeactivateTrace")
	}
	v := s15.DeactivateTrace{ProtocolIEs: make(s08.DeactivateTraceIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDeactivateTraceBudget(&v, budget)
	if err != nil {
		return s15.DeactivateTrace{}, aper.OperationError(err, "DeactivateTrace")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s15.DeactivateTrace{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "DeactivateTrace")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s15.DeactivateTrace{}, aper.OperationError(&s21.BuildError{Issues: issues}, "DeactivateTrace")
	}
	if _, err := s15.BridgeDeactivateTraceMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s15.DeactivateTrace{}, aper.OperationError(fmt.Errorf("%s %w", "DeactivateTrace.protocolIEs:", err), "DeactivateTrace")
	}
	return v, aper.OperationError(nil, "DeactivateTrace")
}
func NewTraceFailureIndication(fields s21.TraceFailureIndicationIEContainer, options ...aper.BuildOption) (s35.TraceFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.TraceFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	v := s35.TraceFailureIndication{ProtocolIEs: make(s21.TraceFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateTraceFailureIndicationBudget(&v, budget)
	if err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "TraceFailureIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s35.TraceFailureIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "TraceFailureIndication")
	}
	if _, err := s35.BridgeTraceFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "TraceFailureIndication.protocolIEs:", err), "TraceFailureIndication")
	}
	return v, aper.OperationError(nil, "TraceFailureIndication")
}
func NewENBConfigurationUpdate(fields s44.ENBConfigurationUpdateIEContainer, options ...aper.BuildOption) (s44.ENBConfigurationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.ENBConfigurationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s44.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	v := s44.ENBConfigurationUpdate{ProtocolIEs: make(s44.ENBConfigurationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateBudget(&v, budget)
	if err != nil {
		return s44.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.ENBConfigurationUpdate{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdate")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.ENBConfigurationUpdate{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBConfigurationUpdate")
	}
	if _, err := s44.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.ENBConfigurationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdate.protocolIEs:", err), "ENBConfigurationUpdate")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdate")
}
func NewENBConfigurationUpdateAcknowledge(fields s22.ENBConfigurationUpdateAcknowledgeIEContainer, options ...aper.BuildOption) (s24.ENBConfigurationUpdateAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.ENBConfigurationUpdateAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s24.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	v := s24.ENBConfigurationUpdateAcknowledge{ProtocolIEs: make(s22.ENBConfigurationUpdateAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateAcknowledgeBudget(&v, budget)
	if err != nil {
		return s24.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s24.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdateAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s24.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBConfigurationUpdateAcknowledge")
	}
	if _, err := s24.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s24.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdateAcknowledge.protocolIEs:", err), "ENBConfigurationUpdateAcknowledge")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdateAcknowledge")
}
func NewENBConfigurationUpdateFailure(fields s22.ENBConfigurationUpdateFailureIEContainer, options ...aper.BuildOption) (s24.ENBConfigurationUpdateFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s24.ENBConfigurationUpdateFailure{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.ENBConfigurationUpdateFailureIEField](bb, uint64(len(fields))); err != nil {
		return s24.ENBConfigurationUpdateFailure{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	v := s24.ENBConfigurationUpdateFailure{ProtocolIEs: make(s22.ENBConfigurationUpdateFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateFailureBudget(&v, budget)
	if err != nil {
		return s24.ENBConfigurationUpdateFailure{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s24.ENBConfigurationUpdateFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdateFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s24.ENBConfigurationUpdateFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBConfigurationUpdateFailure")
	}
	if _, err := s24.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s24.ENBConfigurationUpdateFailure{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdateFailure.protocolIEs:", err), "ENBConfigurationUpdateFailure")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdateFailure")
}
func NewMMEConfigurationUpdate(fields s43.MMEConfigurationUpdateIEContainer, options ...aper.BuildOption) (s44.MMEConfigurationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.MMEConfigurationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s44.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	v := s44.MMEConfigurationUpdate{ProtocolIEs: make(s43.MMEConfigurationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateBudget(&v, budget)
	if err != nil {
		return s44.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.MMEConfigurationUpdate{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdate")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.MMEConfigurationUpdate{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEConfigurationUpdate")
	}
	if _, err := s44.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.MMEConfigurationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdate.protocolIEs:", err), "MMEConfigurationUpdate")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdate")
}
func NewMMEConfigurationUpdateAcknowledge(fields s23.MMEConfigurationUpdateAcknowledgeIEContainer, options ...aper.BuildOption) (s25.MMEConfigurationUpdateAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.MMEConfigurationUpdateAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s25.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	v := s25.MMEConfigurationUpdateAcknowledge{ProtocolIEs: make(s23.MMEConfigurationUpdateAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(&v, budget)
	if err != nil {
		return s25.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdateAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEConfigurationUpdateAcknowledge")
	}
	if _, err := s25.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdateAcknowledge.protocolIEs:", err), "MMEConfigurationUpdateAcknowledge")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdateAcknowledge")
}
func NewMMEConfigurationUpdateFailure(fields s23.MMEConfigurationUpdateFailureIEContainer, options ...aper.BuildOption) (s26.MMEConfigurationUpdateFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s26.MMEConfigurationUpdateFailure{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.MMEConfigurationUpdateFailureIEField](bb, uint64(len(fields))); err != nil {
		return s26.MMEConfigurationUpdateFailure{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	v := s26.MMEConfigurationUpdateFailure{ProtocolIEs: make(s23.MMEConfigurationUpdateFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateFailureBudget(&v, budget)
	if err != nil {
		return s26.MMEConfigurationUpdateFailure{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s26.MMEConfigurationUpdateFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdateFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s26.MMEConfigurationUpdateFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEConfigurationUpdateFailure")
	}
	if _, err := s26.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s26.MMEConfigurationUpdateFailure{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdateFailure.protocolIEs:", err), "MMEConfigurationUpdateFailure")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdateFailure")
}
func NewLocationReportingControl(fields s26.LocationReportingControlIEContainer, options ...aper.BuildOption) (s26.LocationReportingControl, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s26.LocationReportingControl{}, aper.OperationError(err, "LocationReportingControl")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.LocationReportingControlIEField](bb, uint64(len(fields))); err != nil {
		return s26.LocationReportingControl{}, aper.OperationError(err, "LocationReportingControl")
	}
	v := s26.LocationReportingControl{ProtocolIEs: make(s26.LocationReportingControlIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportingControlBudget(&v, budget)
	if err != nil {
		return s26.LocationReportingControl{}, aper.OperationError(err, "LocationReportingControl")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s26.LocationReportingControl{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "LocationReportingControl")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s26.LocationReportingControl{}, aper.OperationError(&s21.BuildError{Issues: issues}, "LocationReportingControl")
	}
	if _, err := s26.BridgeLocationReportingControlMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s26.LocationReportingControl{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReportingControl.protocolIEs:", err), "LocationReportingControl")
	}
	return v, aper.OperationError(nil, "LocationReportingControl")
}
func NewLocationReportingFailureIndication(fields s19.LocationReportingFailureIndicationIEContainer, options ...aper.BuildOption) (s25.LocationReportingFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.LocationReportingFailureIndication{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s19.LocationReportingFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s25.LocationReportingFailureIndication{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	v := s25.LocationReportingFailureIndication{ProtocolIEs: make(s19.LocationReportingFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportingFailureIndicationBudget(&v, budget)
	if err != nil {
		return s25.LocationReportingFailureIndication{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s25.LocationReportingFailureIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "LocationReportingFailureIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.LocationReportingFailureIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "LocationReportingFailureIndication")
	}
	if _, err := s25.BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.LocationReportingFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReportingFailureIndication.protocolIEs:", err), "LocationReportingFailureIndication")
	}
	return v, aper.OperationError(nil, "LocationReportingFailureIndication")
}
func NewLocationReport(fields s32.LocationReportIEContainer, options ...aper.BuildOption) (s33.LocationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s32.LocationReportIEField](bb, uint64(len(fields))); err != nil {
		return s33.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	v := s33.LocationReport{ProtocolIEs: make(s32.LocationReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportBudget(&v, budget)
	if err != nil {
		return s33.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s33.LocationReport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "LocationReport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s33.LocationReport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "LocationReport")
	}
	if _, err := s33.BridgeLocationReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s33.LocationReport{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReport.protocolIEs:", err), "LocationReport")
	}
	return v, aper.OperationError(nil, "LocationReport")
}
func NewOverloadStart(fields s42.OverloadStartIEContainer, options ...aper.BuildOption) (s42.OverloadStart, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.OverloadStart{}, aper.OperationError(err, "OverloadStart")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s42.OverloadStartIEField](bb, uint64(len(fields))); err != nil {
		return s42.OverloadStart{}, aper.OperationError(err, "OverloadStart")
	}
	v := s42.OverloadStart{ProtocolIEs: make(s42.OverloadStartIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOverloadStartBudget(&v, budget)
	if err != nil {
		return s42.OverloadStart{}, aper.OperationError(err, "OverloadStart")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s42.OverloadStart{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "OverloadStart")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s42.OverloadStart{}, aper.OperationError(&s21.BuildError{Issues: issues}, "OverloadStart")
	}
	if _, err := s42.BridgeOverloadStartMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s42.OverloadStart{}, aper.OperationError(fmt.Errorf("%s %w", "OverloadStart.protocolIEs:", err), "OverloadStart")
	}
	return v, aper.OperationError(nil, "OverloadStart")
}
func NewOverloadStop(fields s42.OverloadStopIEContainer, options ...aper.BuildOption) (s42.OverloadStop, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.OverloadStop{}, aper.OperationError(err, "OverloadStop")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s42.OverloadStopIEField](bb, uint64(len(fields))); err != nil {
		return s42.OverloadStop{}, aper.OperationError(err, "OverloadStop")
	}
	v := s42.OverloadStop{ProtocolIEs: make(s42.OverloadStopIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOverloadStopBudget(&v, budget)
	if err != nil {
		return s42.OverloadStop{}, aper.OperationError(err, "OverloadStop")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s42.OverloadStop{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "OverloadStop")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s42.OverloadStop{}, aper.OperationError(&s21.BuildError{Issues: issues}, "OverloadStop")
	}
	if _, err := s42.BridgeOverloadStopMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s42.OverloadStop{}, aper.OperationError(fmt.Errorf("%s %w", "OverloadStop.protocolIEs:", err), "OverloadStop")
	}
	return v, aper.OperationError(nil, "OverloadStop")
}
func NewENBDirectInformationTransfer(fields s34.ENBDirectInformationTransferIEContainer, options ...aper.BuildOption) (s34.ENBDirectInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s34.ENBDirectInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	v := s34.ENBDirectInformationTransfer{ProtocolIEs: make(s34.ENBDirectInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBDirectInformationTransferBudget(&v, budget)
	if err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBDirectInformationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBDirectInformationTransfer")
	}
	if _, err := s34.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBDirectInformationTransfer.protocolIEs:", err), "ENBDirectInformationTransfer")
	}
	return v, aper.OperationError(nil, "ENBDirectInformationTransfer")
}
func NewMMEDirectInformationTransfer(fields s34.MMEDirectInformationTransferIEContainer, options ...aper.BuildOption) (s34.MMEDirectInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s34.MMEDirectInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	v := s34.MMEDirectInformationTransfer{ProtocolIEs: make(s34.MMEDirectInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEDirectInformationTransferBudget(&v, budget)
	if err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEDirectInformationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEDirectInformationTransfer")
	}
	if _, err := s34.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEDirectInformationTransfer.protocolIEs:", err), "MMEDirectInformationTransfer")
	}
	return v, aper.OperationError(nil, "MMEDirectInformationTransfer")
}
func NewCellTrafficTrace(fields s17.CellTrafficTraceIEContainer, options ...aper.BuildOption) (s21.CellTrafficTrace, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.CellTrafficTrace{}, aper.OperationError(err, "CellTrafficTrace")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s17.CellTrafficTraceIEField](bb, uint64(len(fields))); err != nil {
		return s21.CellTrafficTrace{}, aper.OperationError(err, "CellTrafficTrace")
	}
	v := s21.CellTrafficTrace{ProtocolIEs: make(s17.CellTrafficTraceIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateCellTrafficTraceBudget(&v, budget)
	if err != nil {
		return s21.CellTrafficTrace{}, aper.OperationError(err, "CellTrafficTrace")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s21.CellTrafficTrace{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "CellTrafficTrace")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s21.CellTrafficTrace{}, aper.OperationError(&s21.BuildError{Issues: issues}, "CellTrafficTrace")
	}
	if _, err := s21.BridgeCellTrafficTraceMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s21.CellTrafficTrace{}, aper.OperationError(fmt.Errorf("%s %w", "CellTrafficTrace.protocolIEs:", err), "CellTrafficTrace")
	}
	return v, aper.OperationError(nil, "CellTrafficTrace")
}
func NewKillResponse(fields s33.KillResponseIEContainer, options ...aper.BuildOption) (s33.KillResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s33.KillResponseIEField](bb, uint64(len(fields))); err != nil {
		return s33.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	v := s33.KillResponse{ProtocolIEs: make(s33.KillResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateKillResponseBudget(&v, budget)
	if err != nil {
		return s33.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s33.KillResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "KillResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s33.KillResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "KillResponse")
	}
	if _, err := s33.BridgeKillResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s33.KillResponse{}, aper.OperationError(fmt.Errorf("%s %w", "KillResponse.protocolIEs:", err), "KillResponse")
	}
	return v, aper.OperationError(nil, "KillResponse")
}
func NewDownlinkUEAssociatedLPPaTransport(fields s08.DownlinkUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s15.DownlinkUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s08.DownlinkUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s15.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	v := s15.DownlinkUEAssociatedLPPaTransport{ProtocolIEs: make(s08.DownlinkUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s15.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s15.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "DownlinkUEAssociatedLPPaTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s15.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "DownlinkUEAssociatedLPPaTransport")
	}
	if _, err := s15.BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s15.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkUEAssociatedLPPaTransport.protocolIEs:", err), "DownlinkUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "DownlinkUEAssociatedLPPaTransport")
}
func NewDownlinkNonUEAssociatedLPPaTransport(fields s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s15.DownlinkNonUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s08.DownlinkNonUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s15.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	v := s15.DownlinkNonUEAssociatedLPPaTransport{ProtocolIEs: make(s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s15.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s15.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "DownlinkNonUEAssociatedLPPaTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s15.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "DownlinkNonUEAssociatedLPPaTransport")
	}
	if _, err := s15.BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s15.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkNonUEAssociatedLPPaTransport.protocolIEs:", err), "DownlinkNonUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "DownlinkNonUEAssociatedLPPaTransport")
}
func NewPWSRestartIndication(fields s44.PWSRestartIndicationIEContainer, options ...aper.BuildOption) (s44.PWSRestartIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.PWSRestartIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	v := s44.PWSRestartIndication{ProtocolIEs: make(s44.PWSRestartIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePWSRestartIndicationBudget(&v, budget)
	if err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PWSRestartIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.PWSRestartIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PWSRestartIndication")
	}
	if _, err := s44.BridgePWSRestartIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(fmt.Errorf("%s %w", "PWSRestartIndication.protocolIEs:", err), "PWSRestartIndication")
	}
	return v, aper.OperationError(nil, "PWSRestartIndication")
}
func NewERABModificationConfirm(fields s40.ERABModificationConfirmIEContainer, options ...aper.BuildOption) (s40.ERABModificationConfirm, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s40.ERABModificationConfirm{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.ERABModificationConfirmIEField](bb, uint64(len(fields))); err != nil {
		return s40.ERABModificationConfirm{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	v := s40.ERABModificationConfirm{ProtocolIEs: make(s40.ERABModificationConfirmIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModificationConfirmBudget(&v, budget)
	if err != nil {
		return s40.ERABModificationConfirm{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s40.ERABModificationConfirm{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABModificationConfirm")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s40.ERABModificationConfirm{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABModificationConfirm")
	}
	if _, err := s40.BridgeERABModificationConfirmMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s40.ERABModificationConfirm{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModificationConfirm.protocolIEs:", err), "ERABModificationConfirm")
	}
	return v, aper.OperationError(nil, "ERABModificationConfirm")
}
func NewPWSFailureIndication(fields s43.PWSFailureIndicationIEContainer, options ...aper.BuildOption) (s43.PWSFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.PWSFailureIndication{}, aper.OperationError(err, "PWSFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.PWSFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s43.PWSFailureIndication{}, aper.OperationError(err, "PWSFailureIndication")
	}
	v := s43.PWSFailureIndication{ProtocolIEs: make(s43.PWSFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePWSFailureIndicationBudget(&v, budget)
	if err != nil {
		return s43.PWSFailureIndication{}, aper.OperationError(err, "PWSFailureIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s43.PWSFailureIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PWSFailureIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.PWSFailureIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PWSFailureIndication")
	}
	if _, err := s43.BridgePWSFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.PWSFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "PWSFailureIndication.protocolIEs:", err), "PWSFailureIndication")
	}
	return v, aper.OperationError(nil, "PWSFailureIndication")
}
func NewRerouteNASRequest(fields s20.RerouteNASRequestIEContainer, options ...aper.BuildOption) (s27.RerouteNASRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s27.RerouteNASRequest{}, aper.OperationError(err, "RerouteNASRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s20.RerouteNASRequestIEField](bb, uint64(len(fields))); err != nil {
		return s27.RerouteNASRequest{}, aper.OperationError(err, "RerouteNASRequest")
	}
	v := s27.RerouteNASRequest{ProtocolIEs: make(s20.RerouteNASRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateRerouteNASRequestBudget(&v, budget)
	if err != nil {
		return s27.RerouteNASRequest{}, aper.OperationError(err, "RerouteNASRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s27.RerouteNASRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "RerouteNASRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s27.RerouteNASRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "RerouteNASRequest")
	}
	if _, err := s27.BridgeRerouteNASRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s27.RerouteNASRequest{}, aper.OperationError(fmt.Errorf("%s %w", "RerouteNASRequest.protocolIEs:", err), "RerouteNASRequest")
	}
	return v, aper.OperationError(nil, "RerouteNASRequest")
}
func NewConnectionEstablishmentIndication(fields s31.ConnectionEstablishmentIndicationIEContainer, options ...aper.BuildOption) (s31.ConnectionEstablishmentIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s31.ConnectionEstablishmentIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	v := s31.ConnectionEstablishmentIndication{ProtocolIEs: make(s31.ConnectionEstablishmentIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateConnectionEstablishmentIndicationBudget(&v, budget)
	if err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ConnectionEstablishmentIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ConnectionEstablishmentIndication")
	}
	if _, err := s31.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ConnectionEstablishmentIndication.protocolIEs:", err), "ConnectionEstablishmentIndication")
	}
	return v, aper.OperationError(nil, "ConnectionEstablishmentIndication")
}
func NewNASDeliveryIndication(fields s10.NASDeliveryIndicationIEContainer, options ...aper.BuildOption) (s19.NASDeliveryIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.NASDeliveryIndication{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s10.NASDeliveryIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s19.NASDeliveryIndication{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	v := s19.NASDeliveryIndication{ProtocolIEs: make(s10.NASDeliveryIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateNASDeliveryIndicationBudget(&v, budget)
	if err != nil {
		return s19.NASDeliveryIndication{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s19.NASDeliveryIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "NASDeliveryIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s19.NASDeliveryIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "NASDeliveryIndication")
	}
	if _, err := s19.BridgeNASDeliveryIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.NASDeliveryIndication{}, aper.OperationError(fmt.Errorf("%s %w", "NASDeliveryIndication.protocolIEs:", err), "NASDeliveryIndication")
	}
	return v, aper.OperationError(nil, "NASDeliveryIndication")
}
func NewRetrieveUEInformation(fields s28.RetrieveUEInformationIEContainer, options ...aper.BuildOption) (s28.RetrieveUEInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.RetrieveUEInformation{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.RetrieveUEInformationIEField](bb, uint64(len(fields))); err != nil {
		return s28.RetrieveUEInformation{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	v := s28.RetrieveUEInformation{ProtocolIEs: make(s28.RetrieveUEInformationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateRetrieveUEInformationBudget(&v, budget)
	if err != nil {
		return s28.RetrieveUEInformation{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s28.RetrieveUEInformation{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "RetrieveUEInformation")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s28.RetrieveUEInformation{}, aper.OperationError(&s21.BuildError{Issues: issues}, "RetrieveUEInformation")
	}
	if _, err := s28.BridgeRetrieveUEInformationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s28.RetrieveUEInformation{}, aper.OperationError(fmt.Errorf("%s %w", "RetrieveUEInformation.protocolIEs:", err), "RetrieveUEInformation")
	}
	return v, aper.OperationError(nil, "RetrieveUEInformation")
}
func NewMMECPRelocationIndication(fields s10.MMECPRelocationIndicationIEContainer, options ...aper.BuildOption) (s19.MMECPRelocationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MMECPRelocationIndication{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s10.MMECPRelocationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s19.MMECPRelocationIndication{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	v := s19.MMECPRelocationIndication{ProtocolIEs: make(s10.MMECPRelocationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMECPRelocationIndicationBudget(&v, budget)
	if err != nil {
		return s19.MMECPRelocationIndication{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s19.MMECPRelocationIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMECPRelocationIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s19.MMECPRelocationIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMECPRelocationIndication")
	}
	if _, err := s19.BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.MMECPRelocationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "MMECPRelocationIndication.protocolIEs:", err), "MMECPRelocationIndication")
	}
	return v, aper.OperationError(nil, "MMECPRelocationIndication")
}
func NewHandoverSuccess(fields s09.HandoverSuccessIEContainer, options ...aper.BuildOption) (s18.HandoverSuccess, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.HandoverSuccess{}, aper.OperationError(err, "HandoverSuccess")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s09.HandoverSuccessIEField](bb, uint64(len(fields))); err != nil {
		return s18.HandoverSuccess{}, aper.OperationError(err, "HandoverSuccess")
	}
	v := s18.HandoverSuccess{ProtocolIEs: make(s09.HandoverSuccessIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverSuccessBudget(&v, budget)
	if err != nil {
		return s18.HandoverSuccess{}, aper.OperationError(err, "HandoverSuccess")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s18.HandoverSuccess{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverSuccess")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s18.HandoverSuccess{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverSuccess")
	}
	if _, err := s18.BridgeHandoverSuccessMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.HandoverSuccess{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverSuccess.protocolIEs:", err), "HandoverSuccess")
	}
	return v, aper.OperationError(nil, "HandoverSuccess")
}
func NewENBEarlyStatusTransfer(fields s38.ENBEarlyStatusTransferIEContainer, options ...aper.BuildOption) (s38.ENBEarlyStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s38.ENBEarlyStatusTransfer{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s38.ENBEarlyStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s38.ENBEarlyStatusTransfer{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	v := s38.ENBEarlyStatusTransfer{ProtocolIEs: make(s38.ENBEarlyStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBEarlyStatusTransferBudget(&v, budget)
	if err != nil {
		return s38.ENBEarlyStatusTransfer{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s38.ENBEarlyStatusTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBEarlyStatusTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s38.ENBEarlyStatusTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBEarlyStatusTransfer")
	}
	if _, err := s38.BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s38.ENBEarlyStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBEarlyStatusTransfer.protocolIEs:", err), "ENBEarlyStatusTransfer")
	}
	return v, aper.OperationError(nil, "ENBEarlyStatusTransfer")
}
func NewMMEEarlyStatusTransfer(fields s38.MMEEarlyStatusTransferIEContainer, options ...aper.BuildOption) (s38.MMEEarlyStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s38.MMEEarlyStatusTransfer{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s38.MMEEarlyStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s38.MMEEarlyStatusTransfer{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	v := s38.MMEEarlyStatusTransfer{ProtocolIEs: make(s38.MMEEarlyStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEEarlyStatusTransferBudget(&v, budget)
	if err != nil {
		return s38.MMEEarlyStatusTransfer{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s38.MMEEarlyStatusTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEEarlyStatusTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s38.MMEEarlyStatusTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEEarlyStatusTransfer")
	}
	if _, err := s38.BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s38.MMEEarlyStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEEarlyStatusTransfer.protocolIEs:", err), "MMEEarlyStatusTransfer")
	}
	return v, aper.OperationError(nil, "MMEEarlyStatusTransfer")
}
func NewS1RemovalRequest(fields s20.S1RemovalRequestIEContainer, options ...aper.BuildOption) (s27.S1RemovalRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s27.S1RemovalRequest{}, aper.OperationError(err, "S1RemovalRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s20.S1RemovalRequestIEField](bb, uint64(len(fields))); err != nil {
		return s27.S1RemovalRequest{}, aper.OperationError(err, "S1RemovalRequest")
	}
	v := s27.S1RemovalRequest{ProtocolIEs: make(s20.S1RemovalRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1RemovalRequestBudget(&v, budget)
	if err != nil {
		return s27.S1RemovalRequest{}, aper.OperationError(err, "S1RemovalRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s27.S1RemovalRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1RemovalRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s27.S1RemovalRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1RemovalRequest")
	}
	if _, err := s27.BridgeS1RemovalRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s27.S1RemovalRequest{}, aper.OperationError(fmt.Errorf("%s %w", "S1RemovalRequest.protocolIEs:", err), "S1RemovalRequest")
	}
	return v, aper.OperationError(nil, "S1RemovalRequest")
}
func NewS1RemovalResponse(fields s23.S1RemovalResponseIEContainer, options ...aper.BuildOption) (s27.S1RemovalResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s27.S1RemovalResponse{}, aper.OperationError(err, "S1RemovalResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.S1RemovalResponseIEField](bb, uint64(len(fields))); err != nil {
		return s27.S1RemovalResponse{}, aper.OperationError(err, "S1RemovalResponse")
	}
	v := s27.S1RemovalResponse{ProtocolIEs: make(s23.S1RemovalResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1RemovalResponseBudget(&v, budget)
	if err != nil {
		return s27.S1RemovalResponse{}, aper.OperationError(err, "S1RemovalResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s27.S1RemovalResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1RemovalResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s27.S1RemovalResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1RemovalResponse")
	}
	if _, err := s27.BridgeS1RemovalResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s27.S1RemovalResponse{}, aper.OperationError(fmt.Errorf("%s %w", "S1RemovalResponse.protocolIEs:", err), "S1RemovalResponse")
	}
	return v, aper.OperationError(nil, "S1RemovalResponse")
}
func NewS1RemovalFailure(fields s23.S1RemovalFailureIEContainer, options ...aper.BuildOption) (s27.S1RemovalFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s27.S1RemovalFailure{}, aper.OperationError(err, "S1RemovalFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.S1RemovalFailureIEField](bb, uint64(len(fields))); err != nil {
		return s27.S1RemovalFailure{}, aper.OperationError(err, "S1RemovalFailure")
	}
	v := s27.S1RemovalFailure{ProtocolIEs: make(s23.S1RemovalFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1RemovalFailureBudget(&v, budget)
	if err != nil {
		return s27.S1RemovalFailure{}, aper.OperationError(err, "S1RemovalFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s27.S1RemovalFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1RemovalFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s27.S1RemovalFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1RemovalFailure")
	}
	if _, err := s27.BridgeS1RemovalFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s27.S1RemovalFailure{}, aper.OperationError(fmt.Errorf("%s %w", "S1RemovalFailure.protocolIEs:", err), "S1RemovalFailure")
	}
	return v, aper.OperationError(nil, "S1RemovalFailure")
}

// PagingIEContainer is ProtocolIE-Container {{PagingIEs}} of TS 36.413: a list of PagingIEField values.
type PagingIEContainer []PagingIEField

// PagingIEField is ProtocolIE-Field {{PagingIEs}} of TS 36.413: an information element field.
type PagingIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PagingIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEField) WithoutReplay() PagingIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PagingIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PagingIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PagingIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero PagingIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}
func BridgePagingIEValueCaptureS1APProtocolIEContainer(v *PagingIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolIEContainer(v *PagingIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingUEIdentityIndexValueIEBinding binds UEIdentityIndexValue to the PagingIEs object set of TS 36.413.
type PagingUEIdentityIndexValueIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEIdentityIndexValueValueCodec
	inject func(s00.UEIdentityIndexValue,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.UEIdentityIndexValue,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingUEIdentityIndexValueIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingUEIdentityIndexValueIEBinding) Codec() s02.UEIdentityIndexValueValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingUEIdentityIndexValueIEBinding) New(value s00.UEIdentityIndexValue,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEIdentityIndexValueValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingUEIdentityIndexValueIEBinding) Get(field *PagingIEField) (*s00.UEIdentityIndexValue,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingUEPagingIDIEBinding binds UEPagingID to the PagingIEs object set of TS 36.413.
type PagingUEPagingIDIEBinding struct {
	info   s00.FieldInfo
	codec  s28.UEPagingIDValueCodec
	inject func(s28.UEPagingID,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s28.UEPagingID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingUEPagingIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingUEPagingIDIEBinding) Codec() s28.UEPagingIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingUEPagingIDIEBinding) New(value s28.UEPagingID,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeUEPagingIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingUEPagingIDIEBinding) Get(field *PagingIEField) (*s28.UEPagingID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingDRXIEBinding binds PagingDRX to the PagingIEs object set of TS 36.413.
type PagingPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingDRXValueCodec
	inject func(s00.PagingDRX,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.PagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingDRXIEBinding) Codec() s01.PagingDRXValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingPagingDRXIEBinding) New(value s00.PagingDRX,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingDRXIEBinding) Get(field *PagingIEField) (*s00.PagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingCNDomainIEBinding binds CNDomain to the PagingIEs object set of TS 36.413.
type PagingCNDomainIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CNDomainValueCodec
	inject func(s00.CNDomain,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.CNDomain,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingCNDomainIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingCNDomainIEBinding) Codec() s00.CNDomainValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingCNDomainIEBinding) New(value s00.CNDomain,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCNDomainValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingCNDomainIEBinding) Get(field *PagingIEField) (*s00.CNDomain,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingTAIListIEBinding binds TAIList to the PagingIEs object set of TS 36.413.
type PagingTAIListIEBinding struct {
	info   s00.FieldInfo
	codec  s34.TAIListValueCodec
	inject func(s34.TAIList,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s34.TAIList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingTAIListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingTAIListIEBinding) Codec() s34.TAIListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingTAIListIEBinding) New(value s34.TAIList,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s34.BridgeTAIListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingTAIListIEBinding) Get(field *PagingIEField) (*s34.TAIList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingCSGIdListIEBinding binds CSGIdList to the PagingIEs object set of TS 36.413.
type PagingCSGIdListIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CSGIdListValueCodec
	inject func(s14.CSGIdList,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s14.CSGIdList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingCSGIdListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingCSGIdListIEBinding) Codec() s14.CSGIdListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingCSGIdListIEBinding) New(value s14.CSGIdList,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCSGIdListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingCSGIdListIEBinding) Get(field *PagingIEField) (*s14.CSGIdList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingPriorityIEBinding binds PagingPriority to the PagingIEs object set of TS 36.413.
type PagingPagingPriorityIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingPriorityValueCodec
	inject func(s00.PagingPriority,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.PagingPriority,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingPriorityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingPriorityIEBinding) Codec() s01.PagingPriorityValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingPagingPriorityIEBinding) New(value s00.PagingPriority,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingPriorityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingPriorityIEBinding) Get(field *PagingIEField) (*s00.PagingPriority,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingUERadioCapabilityForPagingIEBinding binds UERadioCapabilityForPaging to the PagingIEs object set of TS 36.413.
type PagingUERadioCapabilityForPagingIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityForPagingValueCodec
	inject func(s00.UERadioCapabilityForPaging,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.UERadioCapabilityForPaging,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingUERadioCapabilityForPagingIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingUERadioCapabilityForPagingIEBinding) Codec() s02.UERadioCapabilityForPagingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingUERadioCapabilityForPagingIEBinding) New(value s00.UERadioCapabilityForPaging,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityForPagingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingUERadioCapabilityForPagingIEBinding) Get(field *PagingIEField) (*s00.UERadioCapabilityForPaging,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingAssistanceDataForPagingIEBinding binds AssistanceDataForPaging to the PagingIEs object set of TS 36.413.
type PagingAssistanceDataForPagingIEBinding struct {
	info   s00.FieldInfo
	codec  s26.AssistanceDataForPagingValueCodec
	inject func(s26.AssistanceDataForPaging,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s26.AssistanceDataForPaging,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingAssistanceDataForPagingIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingAssistanceDataForPagingIEBinding) Codec() s26.AssistanceDataForPagingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingAssistanceDataForPagingIEBinding) New(value s26.AssistanceDataForPaging,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeAssistanceDataForPagingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingAssistanceDataForPagingIEBinding) Get(field *PagingIEField) (*s26.AssistanceDataForPaging,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingEDRXInformationIEBinding binds PagingEDRXInformation to the PagingIEs object set of TS 36.413.
type PagingPagingEDRXInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s20.PagingEDRXInformationValueCodec
	inject func(s20.PagingEDRXInformation,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s20.PagingEDRXInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingEDRXInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingEDRXInformationIEBinding) Codec() s20.PagingEDRXInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingPagingEDRXInformationIEBinding) New(value s20.PagingEDRXInformation,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePagingEDRXInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingEDRXInformationIEBinding) Get(field *PagingIEField) (*s20.PagingEDRXInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingExtendedUEIdentityIndexValueIEBinding binds ExtendedUEIdentityIndexValue to the PagingIEs object set of TS 36.413.
type PagingExtendedUEIdentityIndexValueIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ExtendedUEIdentityIndexValueValueCodec
	inject func(s00.ExtendedUEIdentityIndexValue,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.ExtendedUEIdentityIndexValue,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingExtendedUEIdentityIndexValueIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingExtendedUEIdentityIndexValueIEBinding) Codec() s00.ExtendedUEIdentityIndexValueValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingExtendedUEIdentityIndexValueIEBinding) New(value s00.ExtendedUEIdentityIndexValue,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingExtendedUEIdentityIndexValueIEBinding) Get(field *PagingIEField) (*s00.ExtendedUEIdentityIndexValue,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingNBIoTPagingEDRXInformationIEBinding binds NBIoTPagingEDRXInformation to the PagingIEs object set of TS 36.413.
type PagingNBIoTPagingEDRXInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NBIoTPagingEDRXInformationValueCodec
	inject func(s19.NBIoTPagingEDRXInformation,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s19.NBIoTPagingEDRXInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingNBIoTPagingEDRXInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingNBIoTPagingEDRXInformationIEBinding) Codec() s19.NBIoTPagingEDRXInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingNBIoTPagingEDRXInformationIEBinding) New(value s19.NBIoTPagingEDRXInformation,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingNBIoTPagingEDRXInformationIEBinding) Get(field *PagingIEField) (*s19.NBIoTPagingEDRXInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingNBIoTUEIdentityIndexValueIEBinding binds NBIoTUEIdentityIndexValue to the PagingIEs object set of TS 36.413.
type PagingNBIoTUEIdentityIndexValueIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NBIoTUEIdentityIndexValueValueCodec
	inject func(s00.NBIoTUEIdentityIndexValue,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.NBIoTUEIdentityIndexValue,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) Codec() s01.NBIoTUEIdentityIndexValueValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) New(value s00.NBIoTUEIdentityIndexValue,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) Get(field *PagingIEField) (*s00.NBIoTUEIdentityIndexValue,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingEnhancedCoverageRestrictedIEBinding binds EnhancedCoverageRestricted to the PagingIEs object set of TS 36.413.
type PagingEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingEnhancedCoverageRestrictedIEBinding) Get(field *PagingIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingCEModeBRestrictedIEBinding binds CEModeBRestricted to the PagingIEs object set of TS 36.413.
type PagingCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingCEModeBRestrictedIEBinding) Get(field *PagingIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingDataSizeIEBinding binds DataSize to the PagingIEs object set of TS 36.413.
type PagingDataSizeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.DataSizeValueCodec
	inject func(s00.DataSize,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.DataSize,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingDataSizeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingDataSizeIEBinding) Codec() s00.DataSizeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingDataSizeIEBinding) New(value s00.DataSize,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDataSizeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingDataSizeIEBinding) Get(field *PagingIEField) (*s00.DataSize,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingWUSAssistanceInformationIEBinding binds WUSAssistanceInformation to the PagingIEs object set of TS 36.413.
type PagingWUSAssistanceInformationIEBinding struct {
	info   s00.FieldInfo
	codec  WUSAssistanceInformationValueCodec
	inject func(s49.WUSAssistanceInformation,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s49.WUSAssistanceInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingWUSAssistanceInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingWUSAssistanceInformationIEBinding) Codec() WUSAssistanceInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingWUSAssistanceInformationIEBinding) New(value s49.WUSAssistanceInformation,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingWUSAssistanceInformationIEBinding) Get(field *PagingIEField) (*s49.WUSAssistanceInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WUSAssistanceInformationValueCodec is the concrete ValueCodec[WUSAssistanceInformation].
type WUSAssistanceInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s49.WUSAssistanceInformation,

		error)
	encode func(s49.WUSAssistanceInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s49.WUSAssistanceInformation, aper.DecodeState,

	) (s49.WUSAssistanceInformation, aper.Snapshot,

	)
	compare func(s49.WUSAssistanceInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WUSAssistanceInformationValueCodec) New(value s49.WUSAssistanceInformation,

) (WUSAssistanceInformationAPERValue, error) {
	if c.encode == nil {
		return WUSAssistanceInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WUSAssistanceInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WUSAssistanceInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WUSAssistanceInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WUSAssistanceInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WUSAssistanceInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WUSAssistanceInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WUSAssistanceInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WUSAssistanceInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WUSAssistanceInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WUSAssistanceInformationValueCodec) EncodeAPER(value WUSAssistanceInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WUSAssistanceInformationValueCodec) encodeBudgetValue(value s49.WUSAssistanceInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WUSAssistanceInformationValueCodec) encodeChanged(value s49.WUSAssistanceInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingNBIoTPagingDRXIEBinding binds NBIoTPagingDRX to the PagingIEs object set of TS 36.413.
type PagingNBIoTPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NBIoTPagingDRXValueCodec
	inject func(s00.NBIoTPagingDRX,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.NBIoTPagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingNBIoTPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingNBIoTPagingDRXIEBinding) Codec() s01.NBIoTPagingDRXValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingNBIoTPagingDRXIEBinding) New(value s00.NBIoTPagingDRX,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTPagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingNBIoTPagingDRXIEBinding) Get(field *PagingIEField) (*s00.NBIoTPagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingCauseIEBinding binds PagingCause to the PagingIEs object set of TS 36.413.
type PagingPagingCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingCauseValueCodec
	inject func(s00.PagingCause,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.PagingCause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingCauseIEBinding) Codec() s01.PagingCauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingPagingCauseIEBinding) New(value s00.PagingCause,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingCauseIEBinding) Get(field *PagingIEField) (*s00.PagingCause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingValueCodec is the concrete ValueCodec[Paging].
type PagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Paging,

		error)
	encode func(Paging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Paging, aper.DecodeState,

	) (Paging, aper.Snapshot,

	)
	compare func(Paging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingValueCodec) New(value Paging,

) (PagingAPERValue, error) {
	if c.encode == nil {
		return PagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingValueCodec) EncodeAPER(value PagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingValueCodec) encodeBudgetValue(value Paging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingValueCodec) encodeChanged(value Paging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgePagingIEValueValidateS1APIEContainer(fields PagingIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeWUSAssistanceInformationExtIEsValueValidateS1APExtensionContainer(fields s12.WUSAssistanceInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.WUSAssistanceInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.WUSAssistanceInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWUSAssistanceInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// PagingIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PagingIEs}} codec of TS 36.413.
func PagingIEValueERABIEContainerListCodec(table s00.PagingIEValueIETable) PagingIEValueERABIEContainerListValueCodec {
	codec := PagingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PagingIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PagingIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PagingIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value PagingIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PagingIEContainer(value), fresh, budget)
	}, capture: func(v PagingIEValueERABIEContainerList, options aper.DecodeState) (PagingIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v PagingIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePagingIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// WUSAssistanceInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{WUS-Assistance-Information-ExtIEs}} codec of TS 36.413.
func WUSAssistanceInformationExtIEsValueExtensionTableCodec(table s00.WUSAssistanceInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.WUSAssistanceInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeWUSAssistanceInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.WUSAssistanceInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.WUSAssistanceInformationExtIEsExtContainerValueCodec {
		sealed := s12.WUSAssistanceInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.WUSAssistanceInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.WUSAssistanceInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.WUSAssistanceInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeWUSAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "WUSAssistanceInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.WUSAssistanceInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeWUSAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.WUSAssistanceInformationExtIEsExtContainer, options aper.DecodeState) (s12.WUSAssistanceInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s49.BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.WUSAssistanceInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s49.BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PagingIEs}} codec of TS 36.413.
func PagingIEValueIEFieldTableCodec(table s00.PagingIEValueIETable) PagingIEFieldValueCodec {
	if !*s00.BridgePagingIEValueIETableFieldBound(&table) {
		return PagingIEFieldValueCodec{}
	}
	return PagingIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (PagingIEField, error) {
		var field PagingIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "PagingIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "PagingIEField")
		}
		return field, nil
	}, encode: func(field PagingIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PagingIEField, options aper.DecodeState) (PagingIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PagingIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePagingIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// PagingIEValueIETableCodec constructs the ProtocolIE-Container {{PagingIEs}} codec of TS 36.413.
func PagingIEValueIETableCodec(table s00.PagingIEValueIETable, bounds aper.ListBounds) PagingIEContainerValueCodec {
	if !*s00.BridgePagingIEValueIETableFieldBound(&table) {
		return PagingIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return PagingIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (PagingIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEContainer")
		}
		return fields, nil
	},
		encode: func(fields PagingIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v PagingIEContainer, options aper.DecodeState) (PagingIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v PagingIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// PagingIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PagingIEs}} codec of TS 36.413.
func PagingIEValueProtocolErrorIEContainerListCodec(table s00.PagingIEValueIETable) PagingIEValueProtocolErrorIEContainerListValueCodec {
	codec := PagingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PagingIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PagingIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value PagingIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PagingIEContainer(value), fresh, budget)
	}, capture: func(v PagingIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PagingIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePagingIEValueCompareS1APProtocolErrorIEContainerList(
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// PagingIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PagingIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PagingIEValueProtocolIEContainerListCodec(table s00.PagingIEValueIETable, bounds aper.ListBounds) PagingIEValueProtocolIEContainerListValueCodec {
	codec := PagingIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PagingIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return PagingIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PagingIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value PagingIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PagingIEContainer(value), fresh, budget)
	}, capture: func(v PagingIEValueProtocolIEContainerList, options aper.DecodeState) (PagingIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v PagingIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgePagingIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// pagingIEValueProtocolOpenValue is the concrete protocolOpenValue[PagingIEValue].
type PagingIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PagingIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PagingIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingIEValueCaptureS1APProtocolIEField(v *PagingIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgePagingIEValueCompareS1APProtocolIEField(v *PagingIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// wUSAssistanceInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WUSAssistanceInformationExtIEsValue].
type WUSAssistanceInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.WUSAssistanceInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.WUSAssistanceInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// WUSAssistanceInformationAPERValue is the concrete APERValue[WUSAssistanceInformation].
type WUSAssistanceInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s49.WUSAssistanceInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WUSAssistanceInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WUSAssistanceInformationAPERValue) WithoutReplay() WUSAssistanceInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingAPERValue is the concrete APERValue[Paging].
type PagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   Paging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAPERValue) WithoutReplay() PagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeWUSAssistanceInformationExtIEsValueValidateS1APIEContainer(fields s12.WUSAssistanceInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s06.BridgeWUSAssistanceInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeWUSAssistanceInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeWUSAssistanceInformationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// PagingIEValueERABIEContainerListValueCodec is the concrete ValueCodec[PagingIEValueERABIEContainerList].
type PagingIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEValueERABIEContainerList, error)
	encode  func(PagingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEValueERABIEContainerList, aper.DecodeState) (PagingIEValueERABIEContainerList, aper.Snapshot)
	compare func(PagingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEValueERABIEContainerListValueCodec) New(value PagingIEValueERABIEContainerList) (PagingIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEValueERABIEContainerListValueCodec) EncodeAPER(value PagingIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PagingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEValueERABIEContainerListValueCodec) encodeChanged(value PagingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueERABIEContainerList is E-RAB-IE-ContainerList {{PagingIEs}} of TS 36.413: a list of information element fields.
type PagingIEValueERABIEContainerList []PagingIEValueProtocolIESingleContainer

func BridgePagingIEValueCaptureS1APERABIEContainerList(v *PagingIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APERABIEContainerList(v *PagingIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEFieldValueCodec is the concrete ValueCodec[PagingIEField].
type PagingIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEField, error)
	encode  func(PagingIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEField, aper.DecodeState) (PagingIEField, aper.Snapshot)
	compare func(PagingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEFieldValueCodec) New(value PagingIEField) (PagingIEFieldAPERValue, error) {
	if c.encode == nil {
		return PagingIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEFieldValueCodec) EncodeAPER(value PagingIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingIEFieldValueCodec) encodeBudgetValue(value PagingIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEFieldValueCodec) encodeChanged(value PagingIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEContainerValueCodec is the concrete ValueCodec[PagingIEContainer].
type PagingIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEContainer, error)
	encode  func(PagingIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEContainer, aper.DecodeState) (PagingIEContainer, aper.Snapshot)
	compare func(PagingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEContainerValueCodec) New(value PagingIEContainer) (PagingIEContainerAPERValue, error) {
	if c.encode == nil {
		return PagingIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEContainerValueCodec) EncodeAPER(value PagingIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingIEContainerValueCodec) encodeBudgetValue(value PagingIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEContainerValueCodec) encodeChanged(value PagingIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[PagingIEValueProtocolErrorIEContainerList].
type PagingIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, error)
	encode  func(PagingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEValueProtocolErrorIEContainerList, aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PagingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) New(value PagingIEValueProtocolErrorIEContainerList) (PagingIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PagingIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PagingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PagingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{PagingIEs}} of TS 36.413: a list of information element fields.
type PagingIEValueProtocolErrorIEContainerList []PagingIEValueProtocolIESingleContainer

func BridgePagingIEValueCaptureS1APProtocolErrorIEContainerList(v *PagingIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolErrorIEContainerList(v *PagingIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[PagingIEValueProtocolIEContainerList].
type PagingIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEValueProtocolIEContainerList, error)
	encode  func(PagingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEValueProtocolIEContainerList, aper.DecodeState) (PagingIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PagingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEValueProtocolIEContainerListValueCodec) New(value PagingIEValueProtocolIEContainerList) (PagingIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PagingIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PagingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEValueProtocolIEContainerListValueCodec) encodeChanged(value PagingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {PagingIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type PagingIEValueProtocolIEContainerList []PagingIEValueProtocolIESingleContainer

func BridgePagingIEValueCaptureS1APProtocolIEContainerList(v *PagingIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolIEContainerList(v *PagingIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEValueERABIEContainerListAPERValue is the concrete APERValue[PagingIEValueERABIEContainerList].
type PagingIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEValueERABIEContainerListAPERValue) WithoutReplay() PagingIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{PagingIEs}} of TS 36.413: a single information element field.
type PagingIEValueProtocolIESingleContainer = PagingIEField

func BridgePagingIEValueCaptureS1APProtocolIESingleContainer(v *PagingIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolIESingleContainer(v *PagingIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEFieldAPERValue is the concrete APERValue[PagingIEField].
type PagingIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEFieldAPERValue) WithoutReplay() PagingIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEContainerAPERValue is the concrete APERValue[PagingIEContainer].
type PagingIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEContainerAPERValue) WithoutReplay() PagingIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[PagingIEValueProtocolErrorIEContainerList].
type PagingIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PagingIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEValueProtocolIEContainerListAPERValue is the concrete APERValue[PagingIEValueProtocolIEContainerList].
type PagingIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEValueProtocolIEContainerListAPERValue) WithoutReplay() PagingIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APPaging(v *Paging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPaging(v *Paging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPagingIEValue(v *PagingIEValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(80):
			{
				f := s.Begin()
				s.Bool(v.rowUEIdentityIndexValue == nil)
				if v.rowUEIdentityIndexValue != nil {
					s00.BridgeCaptureS1APUEIdentityIndexValue(v.rowUEIdentityIndexValue, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(43):
			{
				f := s.Begin()
				s.Bool(v.rowUEPagingID == nil)
				if v.rowUEPagingID != nil {
					s28.BridgeCaptureS1APUEPagingID(v.rowUEPagingID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(44):
			{
				f := s.Begin()
				s.Bool(v.rowPagingDRX == nil)
				if v.rowPagingDRX != nil {
					s00.BridgeCaptureS1APPagingDRX(v.rowPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(109):
			{
				f := s.Begin()
				s.Bool(v.rowCNDomain == nil)
				if v.rowCNDomain != nil {
					s00.BridgeCaptureS1APCNDomain(v.rowCNDomain, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(46):
			{
				f := s.Begin()
				s.Bool(v.rowTAIList == nil)
				if v.rowTAIList != nil {
					s34.BridgeCaptureS1APTAIList(v.rowTAIList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s21.BridgeCaptureS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(151):
			{
				f := s.Begin()
				s.Bool(v.rowPagingPriority == nil)
				if v.rowPagingPriority != nil {
					s00.BridgeCaptureS1APPagingPriority(v.rowPagingPriority, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(198):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityForPaging == nil)
				if v.rowUERadioCapabilityForPaging != nil {
					s00.BridgeCaptureS1APUERadioCapabilityForPaging(v.rowUERadioCapabilityForPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(211):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceDataForPaging == nil)
				if v.rowAssistanceDataForPaging != nil {
					s26.BridgeCaptureS1APAssistanceDataForPaging(v.rowAssistanceDataForPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(227):
			{
				f := s.Begin()
				s.Bool(v.rowPagingEDRXInformation == nil)
				if v.rowPagingEDRXInformation != nil {
					s20.BridgeCaptureS1APPagingEDRXInformation(v.rowPagingEDRXInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(231):
			{
				f := s.Begin()
				s.Bool(v.rowExtendedUEIdentityIndexValue == nil)
				if v.rowExtendedUEIdentityIndexValue != nil {
					s00.BridgeCaptureS1APExtendedUEIdentityIndexValue(v.rowExtendedUEIdentityIndexValue, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(239):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingEDRXInformation == nil)
				if v.rowNBIoTPagingEDRXInformation != nil {
					s19.BridgeCaptureS1APNBIoTPagingEDRXInformation(v.rowNBIoTPagingEDRXInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(244):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTUEIdentityIndexValue == nil)
				if v.rowNBIoTUEIdentityIndexValue != nil {
					s00.BridgeCaptureS1APNBIoTUEIdentityIndexValue(v.rowNBIoTUEIdentityIndexValue, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s00.BridgeCaptureS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s00.BridgeCaptureS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(304):
			{
				f := s.Begin()
				s.Bool(v.rowDataSize == nil)
				if v.rowDataSize != nil {
					s00.BridgeCaptureS1APDataSize(v.rowDataSize, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(323):
			{
				f := s.Begin()
				s.Bool(v.rowWUSAssistanceInformation == nil)
				if v.rowWUSAssistanceInformation != nil {
					s49.BridgeCaptureS1APWUSAssistanceInformation(v.rowWUSAssistanceInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(324):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingDRX == nil)
				if v.rowNBIoTPagingDRX != nil {
					s00.BridgeCaptureS1APNBIoTPagingDRX(v.rowNBIoTPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(331):
			{
				f := s.Begin()
				s.Bool(v.rowPagingCause == nil)
				if v.rowPagingCause != nil {
					s00.BridgeCaptureS1APPagingCause(v.rowPagingCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PagingIEValue) captureSemantics(s aper.SemanticCapture) PagingIEValue {
	BridgeCaptureS1APPagingIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPagingIEValue(v *PagingIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(80):
			{
				f := s.Begin()
				s.Bool(v.rowUEIdentityIndexValue == nil)
				if v.rowUEIdentityIndexValue != nil {
					s07.BridgeCompareS1APUEIdentityIndexValue(v.rowUEIdentityIndexValue, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(43):
			{
				f := s.Begin()
				s.Bool(v.rowUEPagingID == nil)
				if v.rowUEPagingID != nil {
					s28.BridgeCompareS1APUEPagingID(v.rowUEPagingID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(44):
			{
				f := s.Begin()
				s.Bool(v.rowPagingDRX == nil)
				if v.rowPagingDRX != nil {
					s02.BridgeCompareS1APPagingDRX(v.rowPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(109):
			{
				f := s.Begin()
				s.Bool(v.rowCNDomain == nil)
				if v.rowCNDomain != nil {
					s02.BridgeCompareS1APCNDomain(v.rowCNDomain, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(46):
			{
				f := s.Begin()
				s.Bool(v.rowTAIList == nil)
				if v.rowTAIList != nil {
					s34.BridgeCompareS1APTAIList(v.rowTAIList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s22.BridgeCompareS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(151):
			{
				f := s.Begin()
				s.Bool(v.rowPagingPriority == nil)
				if v.rowPagingPriority != nil {
					s02.BridgeCompareS1APPagingPriority(v.rowPagingPriority, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(198):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityForPaging == nil)
				if v.rowUERadioCapabilityForPaging != nil {
					s07.BridgeCompareS1APUERadioCapabilityForPaging(v.rowUERadioCapabilityForPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(211):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceDataForPaging == nil)
				if v.rowAssistanceDataForPaging != nil {
					s26.BridgeCompareS1APAssistanceDataForPaging(v.rowAssistanceDataForPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(227):
			{
				f := s.Begin()
				s.Bool(v.rowPagingEDRXInformation == nil)
				if v.rowPagingEDRXInformation != nil {
					s20.BridgeCompareS1APPagingEDRXInformation(v.rowPagingEDRXInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(231):
			{
				f := s.Begin()
				s.Bool(v.rowExtendedUEIdentityIndexValue == nil)
				if v.rowExtendedUEIdentityIndexValue != nil {
					s02.BridgeCompareS1APExtendedUEIdentityIndexValue(v.rowExtendedUEIdentityIndexValue, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(239):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingEDRXInformation == nil)
				if v.rowNBIoTPagingEDRXInformation != nil {
					s19.BridgeCompareS1APNBIoTPagingEDRXInformation(v.rowNBIoTPagingEDRXInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(244):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTUEIdentityIndexValue == nil)
				if v.rowNBIoTUEIdentityIndexValue != nil {
					s02.BridgeCompareS1APNBIoTUEIdentityIndexValue(v.rowNBIoTUEIdentityIndexValue, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s02.BridgeCompareS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s02.BridgeCompareS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(304):
			{
				f := s.Begin()
				s.Bool(v.rowDataSize == nil)
				if v.rowDataSize != nil {
					s02.BridgeCompareS1APDataSize(v.rowDataSize, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(323):
			{
				f := s.Begin()
				s.Bool(v.rowWUSAssistanceInformation == nil)
				if v.rowWUSAssistanceInformation != nil {
					s49.BridgeCompareS1APWUSAssistanceInformation(v.rowWUSAssistanceInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(324):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingDRX == nil)
				if v.rowNBIoTPagingDRX != nil {
					s02.BridgeCompareS1APNBIoTPagingDRX(v.rowNBIoTPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(331):
			{
				f := s.Begin()
				s.Bool(v.rowPagingCause == nil)
				if v.rowPagingCause != nil {
					s02.BridgeCompareS1APPagingCause(v.rowPagingCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PagingIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPagingIEValue(&v, &s)
	return s
}

// Paging represents the ASN.1 type Paging (SEQUENCE).
type Paging struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      PagingIEContainer      `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                   `asn1:"-" json:"-"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes Paging to APER format.
func (v *Paging) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *Paging) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes Paging from APER format.
func (v *Paging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Paging with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Paging) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	bb.EnterComponent("Paging")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	padding, err := aper.CaptureFinalBits(bb, "Paging")
	if err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *Paging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Paging{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(PagingIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem PagingIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Paging) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "Paging", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Paging", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Paging) WithoutReplay() Paging {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Paging
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *Paging) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *Paging) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *Paging) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *Paging) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Paging")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Paging) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Paging")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPaging(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Paging")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Paging")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Paging) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Paging")
}
func (v *Paging) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Paging")
}
func (v *Paging) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPaging(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *Paging) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Paging) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *Paging) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Paging")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Paging
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPaging(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Paging{}
		return report, aper.OperationError(err, "Paging")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Paging")
}

type PagingIEValue struct {
	id                              s00.ProtocolIEID
	received                        aper.WireSpan
	replay                          aper.Snapshot
	opaque                          aper.OpaqueOpenType
	isOpaque                        bool
	rowUEIdentityIndexValue         *s00.UEIdentityIndexValue
	rowUEPagingID                   *s28.UEPagingID
	rowPagingDRX                    *s00.PagingDRX
	rowCNDomain                     *s00.CNDomain
	rowTAIList                      *s34.TAIList
	rowCSGIdList                    *s14.CSGIdList
	rowPagingPriority               *s00.PagingPriority
	rowUERadioCapabilityForPaging   *s00.UERadioCapabilityForPaging
	rowAssistanceDataForPaging      *s26.AssistanceDataForPaging
	rowPagingEDRXInformation        *s20.PagingEDRXInformation
	rowExtendedUEIdentityIndexValue *s00.ExtendedUEIdentityIndexValue
	rowNBIoTPagingEDRXInformation   *s19.NBIoTPagingEDRXInformation
	rowNBIoTUEIdentityIndexValue    *s00.NBIoTUEIdentityIndexValue
	rowEnhancedCoverageRestricted   *s00.EnhancedCoverageRestricted
	rowCEModeBRestricted            *s00.CEModeBRestricted
	rowDataSize                     *s00.DataSize
	rowWUSAssistanceInformation     *s49.WUSAssistanceInformation
	rowNBIoTPagingDRX               *s00.NBIoTPagingDRX
	rowPagingCause                  *s00.PagingCause
}

func (v PagingIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(80):
		return v.rowUEIdentityIndexValue != nil
	case s00.ProtocolIEID(43):
		return v.rowUEPagingID != nil
	case s00.ProtocolIEID(44):
		return v.rowPagingDRX != nil
	case s00.ProtocolIEID(109):
		return v.rowCNDomain != nil
	case s00.ProtocolIEID(46):
		return v.rowTAIList != nil
	case s00.ProtocolIEID(128):
		return v.rowCSGIdList != nil
	case s00.ProtocolIEID(151):
		return v.rowPagingPriority != nil
	case s00.ProtocolIEID(198):
		return v.rowUERadioCapabilityForPaging != nil
	case s00.ProtocolIEID(211):
		return v.rowAssistanceDataForPaging != nil
	case s00.ProtocolIEID(227):
		return v.rowPagingEDRXInformation != nil
	case s00.ProtocolIEID(231):
		return v.rowExtendedUEIdentityIndexValue != nil
	case s00.ProtocolIEID(239):
		return v.rowNBIoTPagingEDRXInformation != nil
	case s00.ProtocolIEID(244):
		return v.rowNBIoTUEIdentityIndexValue != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(304):
		return v.rowDataSize != nil
	case s00.ProtocolIEID(323):
		return v.rowWUSAssistanceInformation != nil
	case s00.ProtocolIEID(324):
		return v.rowNBIoTPagingDRX != nil
	case s00.ProtocolIEID(331):
		return v.rowPagingCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PagingIEValue and reports whether the opaque alternative is selected.
func (v *PagingIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PagingIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs"}}
}
func (PagingIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(80):
		return aper.UnknownSelector
	case s00.ProtocolIEID(43):
		return aper.UnknownSelector
	case s00.ProtocolIEID(44):
		return aper.UnknownSelector
	case s00.ProtocolIEID(109):
		return aper.UnknownSelector
	case s00.ProtocolIEID(46):
		return aper.UnknownSelector
	case s00.ProtocolIEID(128):
		return aper.UnknownSelector
	case s00.ProtocolIEID(151):
		return aper.UnknownSelector
	case s00.ProtocolIEID(198):
		return aper.UnknownSelector
	case s00.ProtocolIEID(211):
		return aper.UnknownSelector
	case s00.ProtocolIEID(227):
		return aper.UnknownSelector
	case s00.ProtocolIEID(231):
		return aper.UnknownSelector
	case s00.ProtocolIEID(239):
		return aper.UnknownSelector
	case s00.ProtocolIEID(244):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(304):
		return aper.UnknownSelector
	case s00.ProtocolIEID(323):
		return aper.UnknownSelector
	case s00.ProtocolIEID(324):
		return aper.UnknownSelector
	case s00.ProtocolIEID(331):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(12):
		return aper.NotInTable
	case s00.ProtocolIEID(13):
		return aper.NotInTable
	case s00.ProtocolIEID(14):
		return aper.NotInTable
	case s00.ProtocolIEID(15):
		return aper.NotInTable
	case s00.ProtocolIEID(16):
		return aper.NotInTable
	case s00.ProtocolIEID(17):
		return aper.NotInTable
	case s00.ProtocolIEID(18):
		return aper.NotInTable
	case s00.ProtocolIEID(19):
		return aper.NotInTable
	case s00.ProtocolIEID(20):
		return aper.NotInTable
	case s00.ProtocolIEID(21):
		return aper.NotInTable
	case s00.ProtocolIEID(22):
		return aper.NotInTable
	case s00.ProtocolIEID(23):
		return aper.NotInTable
	case s00.ProtocolIEID(24):
		return aper.NotInTable
	case s00.ProtocolIEID(25):
		return aper.NotInTable
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsUEIdentityIndexValue returns the selected UEIdentityIndexValue value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsUEIdentityIndexValue() (*s00.UEIdentityIndexValue, bool) {
	if v == nil || v.id != s00.ProtocolIEID(80) || v.rowUEIdentityIndexValue == nil {
		return nil, false
	}
	return v.rowUEIdentityIndexValue, true
}

// AsUEPagingID returns the selected UEPagingID value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsUEPagingID() (*s28.UEPagingID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(43) || v.rowUEPagingID == nil {
		return nil, false
	}
	return v.rowUEPagingID, true
}

// AsPagingDRX returns the selected PagingDRX value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingDRX() (*s00.PagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(44) || v.rowPagingDRX == nil {
		return nil, false
	}
	return v.rowPagingDRX, true
}

// AsCNDomain returns the selected CNDomain value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsCNDomain() (*s00.CNDomain, bool) {
	if v == nil || v.id != s00.ProtocolIEID(109) || v.rowCNDomain == nil {
		return nil, false
	}
	return v.rowCNDomain, true
}

// AsTAIList returns the selected TAIList value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsTAIList() (*s34.TAIList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(46) || v.rowTAIList == nil {
		return nil, false
	}
	return v.rowTAIList, true
}

// AsCSGIdList returns the selected CSGIdList value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsCSGIdList() (*s14.CSGIdList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(128) || v.rowCSGIdList == nil {
		return nil, false
	}
	return v.rowCSGIdList, true
}

// AsPagingPriority returns the selected PagingPriority value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingPriority() (*s00.PagingPriority, bool) {
	if v == nil || v.id != s00.ProtocolIEID(151) || v.rowPagingPriority == nil {
		return nil, false
	}
	return v.rowPagingPriority, true
}

// AsUERadioCapabilityForPaging returns the selected UERadioCapabilityForPaging value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsUERadioCapabilityForPaging() (*s00.UERadioCapabilityForPaging, bool) {
	if v == nil || v.id != s00.ProtocolIEID(198) || v.rowUERadioCapabilityForPaging == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityForPaging, true
}

// AsAssistanceDataForPaging returns the selected AssistanceDataForPaging value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsAssistanceDataForPaging() (*s26.AssistanceDataForPaging, bool) {
	if v == nil || v.id != s00.ProtocolIEID(211) || v.rowAssistanceDataForPaging == nil {
		return nil, false
	}
	return v.rowAssistanceDataForPaging, true
}

// AsPagingEDRXInformation returns the selected PagingEDRXInformation value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingEDRXInformation() (*s20.PagingEDRXInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(227) || v.rowPagingEDRXInformation == nil {
		return nil, false
	}
	return v.rowPagingEDRXInformation, true
}

// AsExtendedUEIdentityIndexValue returns the selected ExtendedUEIdentityIndexValue value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsExtendedUEIdentityIndexValue() (*s00.ExtendedUEIdentityIndexValue, bool) {
	if v == nil || v.id != s00.ProtocolIEID(231) || v.rowExtendedUEIdentityIndexValue == nil {
		return nil, false
	}
	return v.rowExtendedUEIdentityIndexValue, true
}

// AsNBIoTPagingEDRXInformation returns the selected NBIoTPagingEDRXInformation value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsNBIoTPagingEDRXInformation() (*s19.NBIoTPagingEDRXInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(239) || v.rowNBIoTPagingEDRXInformation == nil {
		return nil, false
	}
	return v.rowNBIoTPagingEDRXInformation, true
}

// AsNBIoTUEIdentityIndexValue returns the selected NBIoTUEIdentityIndexValue value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsNBIoTUEIdentityIndexValue() (*s00.NBIoTUEIdentityIndexValue, bool) {
	if v == nil || v.id != s00.ProtocolIEID(244) || v.rowNBIoTUEIdentityIndexValue == nil {
		return nil, false
	}
	return v.rowNBIoTUEIdentityIndexValue, true
}

// AsEnhancedCoverageRestricted returns the selected EnhancedCoverageRestricted value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}

// AsCEModeBRestricted returns the selected CEModeBRestricted value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}

// AsDataSize returns the selected DataSize value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsDataSize() (*s00.DataSize, bool) {
	if v == nil || v.id != s00.ProtocolIEID(304) || v.rowDataSize == nil {
		return nil, false
	}
	return v.rowDataSize, true
}

// AsWUSAssistanceInformation returns the selected WUSAssistanceInformation value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsWUSAssistanceInformation() (*s49.WUSAssistanceInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(323) || v.rowWUSAssistanceInformation == nil {
		return nil, false
	}
	return v.rowWUSAssistanceInformation, true
}

// AsNBIoTPagingDRX returns the selected NBIoTPagingDRX value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsNBIoTPagingDRX() (*s00.NBIoTPagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(324) || v.rowNBIoTPagingDRX == nil {
		return nil, false
	}
	return v.rowNBIoTPagingDRX, true
}

// AsPagingCause returns the selected PagingCause value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingCause() (*s00.PagingCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(331) || v.rowPagingCause == nil {
		return nil, false
	}
	return v.rowPagingCause, true
}
func (v PagingIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PagingIEValue, error) {
	out := PagingIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(80):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UEIdentityIndexValue, error) {
			var v struct{ Value s00.UEIdentityIndexValue }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 10, 10, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowUEIdentityIndexValue = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(43):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.UEPagingID
		child := scope
		if err := s28.BridgeUEPagingIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEPagingID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEPagingID")
		if err != nil {
			return out, err
		}
		*s28.BridgeUEPagingIDFieldPerPadding(&value) = padding.Padding()
		*s28.BridgeUEPagingIDFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeUEPagingIDFieldReceivedBytes(&value))
		*s28.BridgeUEPagingIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEPagingID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(44):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingDRX"})
		value := s00.PagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(109):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CNDomain"})
		value := s00.CNDomain(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CNDomain:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCNDomain = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(46):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s45.BridgeUnmarshalAPERTAIListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TAIList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowTAIList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(128):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERCSGIdListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGIdList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowCSGIdList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(151):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 8, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingPriority"})
		value := s00.PagingPriority(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PagingPriority:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPagingPriority = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(198):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapabilityForPaging, error) {
			var v struct {
				Value s00.UERadioCapabilityForPaging
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapabilityForPaging(val_value)
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowUERadioCapabilityForPaging = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(211):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.AssistanceDataForPaging
		child := scope
		if err := s26.BridgeAssistanceDataForPagingMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "AssistanceDataForPaging:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "AssistanceDataForPaging")
		if err != nil {
			return out, err
		}
		*s26.BridgeAssistanceDataForPagingFieldPerPadding(&value) = padding
		*s26.BridgeAssistanceDataForPagingFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeAssistanceDataForPagingFieldReceivedBytes(&value))
		*s26.BridgeAssistanceDataForPagingFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowAssistanceDataForPaging = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(227):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.PagingEDRXInformation
		child := scope
		if err := s20.BridgePagingEDRXInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PagingEDRXInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PagingEDRXInformation")
		if err != nil {
			return out, err
		}
		*s20.BridgePagingEDRXInformationFieldPerPadding(&value) = padding
		*s20.BridgePagingEDRXInformationFieldReceived(&value) = true
		raw.RetainContents(s20.BridgePagingEDRXInformationFieldReceivedBytes(&value))
		*s20.BridgePagingEDRXInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPagingEDRXInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(231):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ExtendedUEIdentityIndexValue, error) {
			var v struct {
				Value s00.ExtendedUEIdentityIndexValue
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 14, 14, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowExtendedUEIdentityIndexValue = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(239):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NBIoTPagingEDRXInformation
		child := scope
		if err := s19.BridgeNBIoTPagingEDRXInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NBIoTPagingEDRXInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NBIoTPagingEDRXInformation")
		if err != nil {
			return out, err
		}
		*s19.BridgeNBIoTPagingEDRXInformationFieldPerPadding(&value) = padding
		*s19.BridgeNBIoTPagingEDRXInformationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNBIoTPagingEDRXInformationFieldReceivedBytes(&value))
		*s19.BridgeNBIoTPagingEDRXInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNBIoTPagingEDRXInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(244):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.NBIoTUEIdentityIndexValue, error) {
			var v struct{ Value s00.NBIoTUEIdentityIndexValue }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 12, 12, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowNBIoTUEIdentityIndexValue = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(251):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnhancedCoverageRestricted"})
		value := s00.EnhancedCoverageRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EnhancedCoverageRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEnhancedCoverageRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(271):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CEModeBRestricted"})
		value := s00.CEModeBRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CEModeBRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCEModeBRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(304):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound12, true)
		value := s00.DataSize(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DataSize:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDataSize = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(323):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s49.WUSAssistanceInformation
		child := scope
		if err := s49.BridgeWUSAssistanceInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "WUSAssistanceInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WUSAssistanceInformation")
		if err != nil {
			return out, err
		}
		*s49.BridgeWUSAssistanceInformationFieldPerPadding(&value) = padding
		*s49.BridgeWUSAssistanceInformationFieldReceived(&value) = true
		raw.RetainContents(s49.BridgeWUSAssistanceInformationFieldReceivedBytes(&value))
		*s49.BridgeWUSAssistanceInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowWUSAssistanceInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(324):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NBIoTPagingDRX"})
		value := s00.NBIoTPagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NBIoTPagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNBIoTPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(331):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingCause"})
		value := s00.PagingCause(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PagingCause:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPagingCause = &value
		raw.RetainContents(&out.received)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v PagingIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PagingIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if budget == nil {
		var err error
		budget, err = aper.EncodeBudget()
		if err != nil {
			return nil, err
		}
	}
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	case s00.ProtocolIEID(80):
		if v.rowUEIdentityIndexValue == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-UEIdentityIndexValue:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UEIdentityIndexValue, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UEIdentityIndexValue }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 10, 10, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowUEIdentityIndexValue, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(43):
		if v.rowUEPagingID == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-UEPagingID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeUEPagingIDMethodMarshalAPERBudget(v.rowUEPagingID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(44):
		if v.rowPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-pagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPagingDRX), 4, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(109):
		if v.rowCNDomain == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-CNDomain:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCNDomain), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(46):
		if v.rowTAIList == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-TAIList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s45.TAIListComplete{Value: *v.rowTAIList}
		candidate, err := s45.BridgeTAIListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(128):
		if v.rowCSGIdList == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-CSG-IdList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.CSGIdListComplete{Value: *v.rowCSGIdList}
		candidate, err := s38.BridgeCSGIdListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(151):
		if v.rowPagingPriority == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-PagingPriority:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPagingPriority), 8, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(198):
		if v.rowUERadioCapabilityForPaging == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-UERadioCapabilityForPaging:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapabilityForPaging, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.UERadioCapabilityForPaging
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowUERadioCapabilityForPaging, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(211):
		if v.rowAssistanceDataForPaging == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-AssistanceDataForPaging:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeAssistanceDataForPagingMethodMarshalAPERBudget(v.rowAssistanceDataForPaging, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(227):
		if v.rowPagingEDRXInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-Paging-eDRXInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgePagingEDRXInformationMethodMarshalAPERBudget(v.rowPagingEDRXInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(231):
		if v.rowExtendedUEIdentityIndexValue == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-extended-UEIdentityIndexValue:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ExtendedUEIdentityIndexValue, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.ExtendedUEIdentityIndexValue
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 14, 14, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowExtendedUEIdentityIndexValue, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(239):
		if v.rowNBIoTPagingEDRXInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-NB-IoT-Paging-eDRXInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNBIoTPagingEDRXInformationMethodMarshalAPERBudget(v.rowNBIoTPagingEDRXInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(244):
		if v.rowNBIoTUEIdentityIndexValue == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-NB-IoT-UEIdentityIndexValue:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.NBIoTUEIdentityIndexValue, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.NBIoTUEIdentityIndexValue }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 12, 12, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowNBIoTUEIdentityIndexValue, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-EnhancedCoverageRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEnhancedCoverageRestricted), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-CE-ModeBRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCEModeBRestricted), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(304):
		if v.rowDataSize == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-DataSize:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowDataSize, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound12, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(323):
		if v.rowWUSAssistanceInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-WUS-Assistance-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s49.BridgeWUSAssistanceInformationMethodMarshalAPERBudget(v.rowWUSAssistanceInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(324):
		if v.rowNBIoTPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-NB-IoT-PagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNBIoTPagingDRX), 6, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(331):
		if v.rowPagingCause == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-PagingCause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPagingCause), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PagingIEValue:", v.id)
	}
}

type PagingIETable struct{}

func PagingIEs() PagingIETable { return PagingIETable{} }

// ID returns the ASN.1 object-set identity of PagingIETable.
func (PagingIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PagingIETable.
func (PagingIETable) Table() s00.PagingIEValueIETable {
	return func() s00.PagingIEValueIETable {
		sealed := s00.PagingIEValueIETable{}
		*s00.BridgePagingIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PagingIETable) infoUEIdentityIndexValue() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(80), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEIdentityIndexValue"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-UEIdentityIndexValue"}}}
}

// UEIdentityIndexValue returns the typed binding for the UEIdentityIndexValue row of PagingIETable.
func (t PagingIETable) UEIdentityIndexValue() PagingUEIdentityIndexValueIEBinding {
	return PagingUEIdentityIndexValueIEBinding{info: t.infoUEIdentityIndexValue(), codec: func() s02.UEIdentityIndexValueValueCodec {
		sealed := s02.UEIdentityIndexValueValueCodec{}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldPath(&sealed) = "UEIdentityIndexValue"
		*s02.BridgeUEIdentityIndexValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEIdentityIndexValue, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEIdentityIndexValue
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEIdentityIndexValue")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(80), raw)
			if err != nil {
				var empty s00.UEIdentityIndexValue
				return empty, runtime.WrapDecodePath(err, "UEIdentityIndexValue")
			}
			value, ok := decoded.AsUEIdentityIndexValue()
			if !ok {
				var empty s00.UEIdentityIndexValue
				return empty, fmt.Errorf("binding PagingIEs.id-UEIdentityIndexValue: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldEncode(&sealed) = func(value s00.UEIdentityIndexValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(80), rowUEIdentityIndexValue: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldCapture(&sealed) = func(v s00.UEIdentityIndexValue, options aper.DecodeState) (s00.UEIdentityIndexValue, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEIdentityIndexValue(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldCompare(&sealed) = func(v s00.UEIdentityIndexValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUEIdentityIndexValue(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEIdentityIndexValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEIdentityIndexValue) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(80), rowUEIdentityIndexValue: &value}
		}, get: func(value *PagingIEValue) (*s00.UEIdentityIndexValue, bool) { return value.AsUEIdentityIndexValue() }}
}
func (PagingIETable) infoUEPagingID() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(43), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEPagingID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-UEPagingID"}}}
}

// UEPagingID returns the typed binding for the UEPagingID row of PagingIETable.
func (t PagingIETable) UEPagingID() PagingUEPagingIDIEBinding {
	return PagingUEPagingIDIEBinding{info: t.infoUEPagingID(), codec: func() s28.UEPagingIDValueCodec {
		sealed := s28.UEPagingIDValueCodec{}
		*s28.BridgeUEPagingIDValueCodecFieldPath(&sealed) = "UEPagingID"
		*s28.BridgeUEPagingIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UEPagingID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.UEPagingID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEPagingID")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(43), raw)
			if err != nil {
				var empty s28.UEPagingID
				return empty, runtime.WrapDecodePath(err, "UEPagingID")
			}
			value, ok := decoded.AsUEPagingID()
			if !ok {
				var empty s28.UEPagingID
				return empty, fmt.Errorf("binding PagingIEs.id-UEPagingID: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeUEPagingIDValueCodecFieldEncode(&sealed) = func(value s28.UEPagingID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(43), rowUEPagingID: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeUEPagingIDValueCodecFieldCapture(&sealed) = func(v s28.UEPagingID, options aper.DecodeState) (s28.UEPagingID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s28.BridgeCaptureS1APUEPagingID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUEPagingIDValueCodecFieldCompare(&sealed) = func(v s28.UEPagingID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APUEPagingID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEPagingIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEPagingID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.UEPagingID) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(43), rowUEPagingID: &value}
		}, get: func(value *PagingIEValue) (*s28.UEPagingID, bool) { return value.AsUEPagingID() }}
}
func (PagingIETable) infoPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(44), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-pagingDRX"}}}
}

// PagingDRX returns the typed binding for the PagingDRX row of PagingIETable.
func (t PagingIETable) PagingDRX() PagingPagingDRXIEBinding {
	return PagingPagingDRXIEBinding{info: t.infoPagingDRX(), codec: func() s01.PagingDRXValueCodec {
		sealed := s01.PagingDRXValueCodec{}
		*s01.BridgePagingDRXValueCodecFieldPath(&sealed) = "PagingDRX"
		*s01.BridgePagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingDRX")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(44), raw)
			if err != nil {
				var empty s00.PagingDRX
				return empty, runtime.WrapDecodePath(err, "PagingDRX")
			}
			value, ok := decoded.AsPagingDRX()
			if !ok {
				var empty s00.PagingDRX
				return empty, fmt.Errorf("binding PagingIEs.id-pagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingDRXValueCodecFieldEncode(&sealed) = func(value s00.PagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(44), rowPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingDRXValueCodecFieldCapture(&sealed) = func(v s00.PagingDRX, options aper.DecodeState) (s00.PagingDRX, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingDRXValueCodecFieldCompare(&sealed) = func(v s00.PagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingDRX(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingDRX) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(44), rowPagingDRX: &value}
		}, get: func(value *PagingIEValue) (*s00.PagingDRX, bool) { return value.AsPagingDRX() }}
}
func (PagingIETable) infoCNDomain() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(109), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CNDomain"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-CNDomain"}}}
}

// CNDomain returns the typed binding for the CNDomain row of PagingIETable.
func (t PagingIETable) CNDomain() PagingCNDomainIEBinding {
	return PagingCNDomainIEBinding{info: t.infoCNDomain(), codec: func() s00.CNDomainValueCodec {
		sealed := s00.CNDomainValueCodec{}
		*s00.BridgeCNDomainValueCodecFieldPath(&sealed) = "CNDomain"
		*s00.BridgeCNDomainValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CNDomain, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CNDomain
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CNDomain")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(109), raw)
			if err != nil {
				var empty s00.CNDomain
				return empty, runtime.WrapDecodePath(err, "CNDomain")
			}
			value, ok := decoded.AsCNDomain()
			if !ok {
				var empty s00.CNDomain
				return empty, fmt.Errorf("binding PagingIEs.id-CNDomain: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCNDomainValueCodecFieldEncode(&sealed) = func(value s00.CNDomain, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(109), rowCNDomain: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCNDomainValueCodecFieldCapture(&sealed) = func(v s00.CNDomain, options aper.DecodeState) (s00.CNDomain, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCNDomain(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCNDomainValueCodecFieldCompare(&sealed) = func(v s00.CNDomain, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCNDomain(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCNDomainValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CNDomain"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CNDomain) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(109), rowCNDomain: &value}
		}, get: func(value *PagingIEValue) (*s00.CNDomain, bool) { return value.AsCNDomain() }}
}
func (PagingIETable) infoTAIList() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(46), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-TAIList"}}}
}

// TAIList returns the typed binding for the TAIList row of PagingIETable.
func (t PagingIETable) TAIList() PagingTAIListIEBinding {
	return PagingTAIListIEBinding{info: t.infoTAIList(), codec: func() s34.TAIListValueCodec {
		sealed := s34.TAIListValueCodec{}
		*s34.BridgeTAIListValueCodecFieldPath(&sealed) = "TAIList"
		*s34.BridgeTAIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.TAIList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s34.TAIList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAIList")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(46), raw)
			if err != nil {
				var empty s34.TAIList
				return empty, runtime.WrapDecodePath(err, "TAIList")
			}
			value, ok := decoded.AsTAIList()
			if !ok {
				var empty s34.TAIList
				return empty, fmt.Errorf("binding PagingIEs.id-TAIList: no selected value")
			}
			return *value, nil
		}
		*s34.BridgeTAIListValueCodecFieldEncode(&sealed) = func(value s34.TAIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(46), rowTAIList: &value}).encodeFresh(fresh, budget)
		}
		*s34.BridgeTAIListValueCodecFieldCapture(&sealed) = func(v s34.TAIList, options aper.DecodeState) (s34.TAIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s34.BridgeCaptureS1APTAIList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s34.BridgeTAIListValueCodecFieldCompare(&sealed) = func(v s34.TAIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s34.BridgeCompareS1APTAIList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s34.BridgeTAIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s34.TAIList) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(46), rowTAIList: &value}
		}, get: func(value *PagingIEValue) (*s34.TAIList, bool) { return value.AsTAIList() }}
}
func (PagingIETable) infoCSGIdList() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(128), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-IdList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-CSG-IdList"}}}
}

// CSGIdList returns the typed binding for the CSGIdList row of PagingIETable.
func (t PagingIETable) CSGIdList() PagingCSGIdListIEBinding {
	return PagingCSGIdListIEBinding{info: t.infoCSGIdList(), codec: func() s14.CSGIdListValueCodec {
		sealed := s14.CSGIdListValueCodec{}
		*s14.BridgeCSGIdListValueCodecFieldPath(&sealed) = "CSGIdList"
		*s14.BridgeCSGIdListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CSGIdList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.CSGIdList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGIdList")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(128), raw)
			if err != nil {
				var empty s14.CSGIdList
				return empty, runtime.WrapDecodePath(err, "CSGIdList")
			}
			value, ok := decoded.AsCSGIdList()
			if !ok {
				var empty s14.CSGIdList
				return empty, fmt.Errorf("binding PagingIEs.id-CSG-IdList: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCSGIdListValueCodecFieldEncode(&sealed) = func(value s14.CSGIdList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCSGIdListValueCodecFieldCapture(&sealed) = func(v s14.CSGIdList, options aper.DecodeState) (s14.CSGIdList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s21.BridgeCaptureS1APCSGIdList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeCSGIdListValueCodecFieldCompare(&sealed) = func(v s14.CSGIdList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCSGIdList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCSGIdListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.CSGIdList) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}
		}, get: func(value *PagingIEValue) (*s14.CSGIdList, bool) { return value.AsCSGIdList() }}
}
func (PagingIETable) infoPagingPriority() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(151), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingPriority"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-PagingPriority"}}}
}

// PagingPriority returns the typed binding for the PagingPriority row of PagingIETable.
func (t PagingIETable) PagingPriority() PagingPagingPriorityIEBinding {
	return PagingPagingPriorityIEBinding{info: t.infoPagingPriority(), codec: func() s01.PagingPriorityValueCodec {
		sealed := s01.PagingPriorityValueCodec{}
		*s01.BridgePagingPriorityValueCodecFieldPath(&sealed) = "PagingPriority"
		*s01.BridgePagingPriorityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingPriority, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingPriority
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingPriority")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(151), raw)
			if err != nil {
				var empty s00.PagingPriority
				return empty, runtime.WrapDecodePath(err, "PagingPriority")
			}
			value, ok := decoded.AsPagingPriority()
			if !ok {
				var empty s00.PagingPriority
				return empty, fmt.Errorf("binding PagingIEs.id-PagingPriority: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingPriorityValueCodecFieldEncode(&sealed) = func(value s00.PagingPriority, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(151), rowPagingPriority: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingPriorityValueCodecFieldCapture(&sealed) = func(v s00.PagingPriority, options aper.DecodeState) (s00.PagingPriority, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingPriority(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingPriorityValueCodecFieldCompare(&sealed) = func(v s00.PagingPriority, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingPriority(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingPriorityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingPriority"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingPriority) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(151), rowPagingPriority: &value}
		}, get: func(value *PagingIEValue) (*s00.PagingPriority, bool) { return value.AsPagingPriority() }}
}
func (PagingIETable) infoUERadioCapabilityForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(198), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-UERadioCapabilityForPaging"}}}
}

// UERadioCapabilityForPaging returns the typed binding for the UERadioCapabilityForPaging row of PagingIETable.
func (t PagingIETable) UERadioCapabilityForPaging() PagingUERadioCapabilityForPagingIEBinding {
	return PagingUERadioCapabilityForPagingIEBinding{info: t.infoUERadioCapabilityForPaging(), codec: func() s02.UERadioCapabilityForPagingValueCodec {
		sealed := s02.UERadioCapabilityForPagingValueCodec{}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldPath(&sealed) = "UERadioCapabilityForPaging"
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityForPaging, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityForPaging
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityForPaging")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(198), raw)
			if err != nil {
				var empty s00.UERadioCapabilityForPaging
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityForPaging")
			}
			value, ok := decoded.AsUERadioCapabilityForPaging()
			if !ok {
				var empty s00.UERadioCapabilityForPaging
				return empty, fmt.Errorf("binding PagingIEs.id-UERadioCapabilityForPaging: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(198), rowUERadioCapabilityForPaging: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapabilityForPaging, options aper.DecodeState) (s00.UERadioCapabilityForPaging, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapabilityForPaging(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapabilityForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERadioCapabilityForPaging(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityForPaging"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapabilityForPaging) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(198), rowUERadioCapabilityForPaging: &value}
		}, get: func(value *PagingIEValue) (*s00.UERadioCapabilityForPaging, bool) {
			return value.AsUERadioCapabilityForPaging()
		}}
}
func (PagingIETable) infoAssistanceDataForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(211), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AssistanceDataForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-AssistanceDataForPaging"}}}
}

// AssistanceDataForPaging returns the typed binding for the AssistanceDataForPaging row of PagingIETable.
func (t PagingIETable) AssistanceDataForPaging() PagingAssistanceDataForPagingIEBinding {
	return PagingAssistanceDataForPagingIEBinding{info: t.infoAssistanceDataForPaging(), codec: func() s26.AssistanceDataForPagingValueCodec {
		sealed := s26.AssistanceDataForPagingValueCodec{}
		*s26.BridgeAssistanceDataForPagingValueCodecFieldPath(&sealed) = "AssistanceDataForPaging"
		*s26.BridgeAssistanceDataForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.AssistanceDataForPaging, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.AssistanceDataForPaging
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AssistanceDataForPaging")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(211), raw)
			if err != nil {
				var empty s26.AssistanceDataForPaging
				return empty, runtime.WrapDecodePath(err, "AssistanceDataForPaging")
			}
			value, ok := decoded.AsAssistanceDataForPaging()
			if !ok {
				var empty s26.AssistanceDataForPaging
				return empty, fmt.Errorf("binding PagingIEs.id-AssistanceDataForPaging: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeAssistanceDataForPagingValueCodecFieldEncode(&sealed) = func(value s26.AssistanceDataForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(211), rowAssistanceDataForPaging: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeAssistanceDataForPagingValueCodecFieldCapture(&sealed) = func(v s26.AssistanceDataForPaging, options aper.DecodeState) (s26.AssistanceDataForPaging, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APAssistanceDataForPaging(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s26.BridgeAssistanceDataForPagingValueCodecFieldCompare(&sealed) = func(v s26.AssistanceDataForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APAssistanceDataForPaging(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeAssistanceDataForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceDataForPaging"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.AssistanceDataForPaging) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(211), rowAssistanceDataForPaging: &value}
		}, get: func(value *PagingIEValue) (*s26.AssistanceDataForPaging, bool) {
			return value.AsAssistanceDataForPaging()
		}}
}
func (PagingIETable) infoPagingEDRXInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(227), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Paging-eDRXInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-Paging-eDRXInformation"}}}
}

// PagingEDRXInformation returns the typed binding for the PagingEDRXInformation row of PagingIETable.
func (t PagingIETable) PagingEDRXInformation() PagingPagingEDRXInformationIEBinding {
	return PagingPagingEDRXInformationIEBinding{info: t.infoPagingEDRXInformation(), codec: func() s20.PagingEDRXInformationValueCodec {
		sealed := s20.PagingEDRXInformationValueCodec{}
		*s20.BridgePagingEDRXInformationValueCodecFieldPath(&sealed) = "PagingEDRXInformation"
		*s20.BridgePagingEDRXInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.PagingEDRXInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.PagingEDRXInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingEDRXInformation")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(227), raw)
			if err != nil {
				var empty s20.PagingEDRXInformation
				return empty, runtime.WrapDecodePath(err, "PagingEDRXInformation")
			}
			value, ok := decoded.AsPagingEDRXInformation()
			if !ok {
				var empty s20.PagingEDRXInformation
				return empty, fmt.Errorf("binding PagingIEs.id-Paging-eDRXInformation: no selected value")
			}
			return *value, nil
		}
		*s20.BridgePagingEDRXInformationValueCodecFieldEncode(&sealed) = func(value s20.PagingEDRXInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(227), rowPagingEDRXInformation: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgePagingEDRXInformationValueCodecFieldCapture(&sealed) = func(v s20.PagingEDRXInformation, options aper.DecodeState) (s20.PagingEDRXInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APPagingEDRXInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s20.BridgePagingEDRXInformationValueCodecFieldCompare(&sealed) = func(v s20.PagingEDRXInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APPagingEDRXInformation(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgePagingEDRXInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingEDRXInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.PagingEDRXInformation) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(227), rowPagingEDRXInformation: &value}
		}, get: func(value *PagingIEValue) (*s20.PagingEDRXInformation, bool) { return value.AsPagingEDRXInformation() }}
}
func (PagingIETable) infoExtendedUEIdentityIndexValue() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(231), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Extended-UEIdentityIndexValue"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-extended-UEIdentityIndexValue"}}}
}

// ExtendedUEIdentityIndexValue returns the typed binding for the ExtendedUEIdentityIndexValue row of PagingIETable.
func (t PagingIETable) ExtendedUEIdentityIndexValue() PagingExtendedUEIdentityIndexValueIEBinding {
	return PagingExtendedUEIdentityIndexValueIEBinding{info: t.infoExtendedUEIdentityIndexValue(), codec: func() s00.ExtendedUEIdentityIndexValueValueCodec {
		sealed := s00.ExtendedUEIdentityIndexValueValueCodec{}
		*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldPath(&sealed) = "ExtendedUEIdentityIndexValue"
		*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedUEIdentityIndexValue, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedUEIdentityIndexValue
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExtendedUEIdentityIndexValue")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(231), raw)
			if err != nil {
				var empty s00.ExtendedUEIdentityIndexValue
				return empty, runtime.WrapDecodePath(err, "ExtendedUEIdentityIndexValue")
			}
			value, ok := decoded.AsExtendedUEIdentityIndexValue()
			if !ok {
				var empty s00.ExtendedUEIdentityIndexValue
				return empty, fmt.Errorf("binding PagingIEs.id-extended-UEIdentityIndexValue: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldEncode(&sealed) = func(value s00.ExtendedUEIdentityIndexValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(231), rowExtendedUEIdentityIndexValue: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldCapture(&sealed) = func(v s00.ExtendedUEIdentityIndexValue, options aper.DecodeState) (s00.ExtendedUEIdentityIndexValue, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedUEIdentityIndexValue(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldCompare(&sealed) = func(v s00.ExtendedUEIdentityIndexValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s02.BridgeCompareS1APExtendedUEIdentityIndexValue(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeExtendedUEIdentityIndexValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedUEIdentityIndexValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedUEIdentityIndexValue) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(231), rowExtendedUEIdentityIndexValue: &value}
		}, get: func(value *PagingIEValue) (*s00.ExtendedUEIdentityIndexValue, bool) {
			return value.AsExtendedUEIdentityIndexValue()
		}}
}
func (PagingIETable) infoNBIoTPagingEDRXInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(239), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-Paging-eDRXInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-NB-IoT-Paging-eDRXInformation"}}}
}

// NBIoTPagingEDRXInformation returns the typed binding for the NBIoTPagingEDRXInformation row of PagingIETable.
func (t PagingIETable) NBIoTPagingEDRXInformation() PagingNBIoTPagingEDRXInformationIEBinding {
	return PagingNBIoTPagingEDRXInformationIEBinding{info: t.infoNBIoTPagingEDRXInformation(), codec: func() s19.NBIoTPagingEDRXInformationValueCodec {
		sealed := s19.NBIoTPagingEDRXInformationValueCodec{}
		*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldPath(&sealed) = "NBIoTPagingEDRXInformation"
		*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NBIoTPagingEDRXInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NBIoTPagingEDRXInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTPagingEDRXInformation")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(239), raw)
			if err != nil {
				var empty s19.NBIoTPagingEDRXInformation
				return empty, runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformation")
			}
			value, ok := decoded.AsNBIoTPagingEDRXInformation()
			if !ok {
				var empty s19.NBIoTPagingEDRXInformation
				return empty, fmt.Errorf("binding PagingIEs.id-NB-IoT-Paging-eDRXInformation: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldEncode(&sealed) = func(value s19.NBIoTPagingEDRXInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(239), rowNBIoTPagingEDRXInformation: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldCapture(&sealed) = func(v s19.NBIoTPagingEDRXInformation, options aper.DecodeState) (s19.NBIoTPagingEDRXInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNBIoTPagingEDRXInformation(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldCompare(&sealed) = func(v s19.NBIoTPagingEDRXInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNBIoTPagingEDRXInformation(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNBIoTPagingEDRXInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTPagingEDRXInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NBIoTPagingEDRXInformation) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(239), rowNBIoTPagingEDRXInformation: &value}
		}, get: func(value *PagingIEValue) (*s19.NBIoTPagingEDRXInformation, bool) {
			return value.AsNBIoTPagingEDRXInformation()
		}}
}
func (PagingIETable) infoNBIoTUEIdentityIndexValue() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(244), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-UEIdentityIndexValue"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-NB-IoT-UEIdentityIndexValue"}}}
}

// NBIoTUEIdentityIndexValue returns the typed binding for the NBIoTUEIdentityIndexValue row of PagingIETable.
func (t PagingIETable) NBIoTUEIdentityIndexValue() PagingNBIoTUEIdentityIndexValueIEBinding {
	return PagingNBIoTUEIdentityIndexValueIEBinding{info: t.infoNBIoTUEIdentityIndexValue(), codec: func() s01.NBIoTUEIdentityIndexValueValueCodec {
		sealed := s01.NBIoTUEIdentityIndexValueValueCodec{}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldPath(&sealed) = "NBIoTUEIdentityIndexValue"
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTUEIdentityIndexValue, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTUEIdentityIndexValue
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTUEIdentityIndexValue")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(244), raw)
			if err != nil {
				var empty s00.NBIoTUEIdentityIndexValue
				return empty, runtime.WrapDecodePath(err, "NBIoTUEIdentityIndexValue")
			}
			value, ok := decoded.AsNBIoTUEIdentityIndexValue()
			if !ok {
				var empty s00.NBIoTUEIdentityIndexValue
				return empty, fmt.Errorf("binding PagingIEs.id-NB-IoT-UEIdentityIndexValue: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldEncode(&sealed) = func(value s00.NBIoTUEIdentityIndexValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(244), rowNBIoTUEIdentityIndexValue: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldCapture(&sealed) = func(v s00.NBIoTUEIdentityIndexValue, options aper.DecodeState) (s00.NBIoTUEIdentityIndexValue, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTUEIdentityIndexValue(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldCompare(&sealed) = func(v s00.NBIoTUEIdentityIndexValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTUEIdentityIndexValue(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTUEIdentityIndexValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTUEIdentityIndexValue) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(244), rowNBIoTUEIdentityIndexValue: &value}
		}, get: func(value *PagingIEValue) (*s00.NBIoTUEIdentityIndexValue, bool) {
			return value.AsNBIoTUEIdentityIndexValue()
		}}
}
func (PagingIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of PagingIETable.
func (t PagingIETable) EnhancedCoverageRestricted() PagingEnhancedCoverageRestrictedIEBinding {
	return PagingEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding PagingIEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCapture(&sealed) = func(v s00.EnhancedCoverageRestricted, options aper.DecodeState) (s00.EnhancedCoverageRestricted, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEnhancedCoverageRestricted(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCompare(&sealed) = func(v s00.EnhancedCoverageRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEnhancedCoverageRestricted(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EnhancedCoverageRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EnhancedCoverageRestricted) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *PagingIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (PagingIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of PagingIETable.
func (t PagingIETable) CEModeBRestricted() PagingCEModeBRestrictedIEBinding {
	return PagingCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding PagingIEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCapture(&sealed) = func(v s00.CEModeBRestricted, options aper.DecodeState) (s00.CEModeBRestricted, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCEModeBRestricted(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCompare(&sealed) = func(v s00.CEModeBRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCEModeBRestricted(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CEModeBRestricted) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *PagingIEValue) (*s00.CEModeBRestricted, bool) { return value.AsCEModeBRestricted() }}
}
func (PagingIETable) infoDataSize() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(304), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DataSize"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-DataSize"}}}
}

// DataSize returns the typed binding for the DataSize row of PagingIETable.
func (t PagingIETable) DataSize() PagingDataSizeIEBinding {
	return PagingDataSizeIEBinding{info: t.infoDataSize(), codec: func() s00.DataSizeValueCodec {
		sealed := s00.DataSizeValueCodec{}
		*s00.BridgeDataSizeValueCodecFieldPath(&sealed) = "DataSize"
		*s00.BridgeDataSizeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DataSize, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DataSize
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DataSize")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(304), raw)
			if err != nil {
				var empty s00.DataSize
				return empty, runtime.WrapDecodePath(err, "DataSize")
			}
			value, ok := decoded.AsDataSize()
			if !ok {
				var empty s00.DataSize
				return empty, fmt.Errorf("binding PagingIEs.id-DataSize: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDataSizeValueCodecFieldEncode(&sealed) = func(value s00.DataSize, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(304), rowDataSize: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDataSizeValueCodecFieldCapture(&sealed) = func(v s00.DataSize, options aper.DecodeState) (s00.DataSize, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APDataSize(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeDataSizeValueCodecFieldCompare(&sealed) = func(v s00.DataSize, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDataSize(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDataSizeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DataSize"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DataSize) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(304), rowDataSize: &value}
		}, get: func(value *PagingIEValue) (*s00.DataSize, bool) { return value.AsDataSize() }}
}
func (PagingIETable) infoWUSAssistanceInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(323), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WUS-Assistance-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-WUS-Assistance-Information"}}}
}

// WUSAssistanceInformation returns the typed binding for the WUSAssistanceInformation row of PagingIETable.
func (t PagingIETable) WUSAssistanceInformation() PagingWUSAssistanceInformationIEBinding {
	return PagingWUSAssistanceInformationIEBinding{info: t.infoWUSAssistanceInformation(), codec: WUSAssistanceInformationValueCodec{path: "WUSAssistanceInformation",
		decode: func(data []byte, options aper.DecodeState) (s49.WUSAssistanceInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s49.WUSAssistanceInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WUSAssistanceInformation")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(323), raw)
			if err != nil {
				var empty s49.WUSAssistanceInformation
				return empty, runtime.WrapDecodePath(err, "WUSAssistanceInformation")
			}
			value, ok := decoded.AsWUSAssistanceInformation()
			if !ok {
				var empty s49.WUSAssistanceInformation
				return empty, fmt.Errorf("binding PagingIEs.id-WUS-Assistance-Information: no selected value")
			}
			return *value, nil
		},
		encode: func(value s49.WUSAssistanceInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(323), rowWUSAssistanceInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s49.WUSAssistanceInformation, options aper.DecodeState) (s49.WUSAssistanceInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s49.BridgeCaptureS1APWUSAssistanceInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v s49.WUSAssistanceInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s49.BridgeCompareS1APWUSAssistanceInformation(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WUSAssistanceInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s49.WUSAssistanceInformation) PagingIEValue {
		return PagingIEValue{id: s00.ProtocolIEID(323), rowWUSAssistanceInformation: &value}
	}, get: func(value *PagingIEValue) (*s49.WUSAssistanceInformation, bool) {
		return value.AsWUSAssistanceInformation()
	}}
}
func (PagingIETable) infoNBIoTPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(324), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-PagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-NB-IoT-PagingDRX"}}}
}

// NBIoTPagingDRX returns the typed binding for the NBIoTPagingDRX row of PagingIETable.
func (t PagingIETable) NBIoTPagingDRX() PagingNBIoTPagingDRXIEBinding {
	return PagingNBIoTPagingDRXIEBinding{info: t.infoNBIoTPagingDRX(), codec: func() s01.NBIoTPagingDRXValueCodec {
		sealed := s01.NBIoTPagingDRXValueCodec{}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldPath(&sealed) = "NBIoTPagingDRX"
		*s01.BridgeNBIoTPagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTPagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTPagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTPagingDRX")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(324), raw)
			if err != nil {
				var empty s00.NBIoTPagingDRX
				return empty, runtime.WrapDecodePath(err, "NBIoTPagingDRX")
			}
			value, ok := decoded.AsNBIoTPagingDRX()
			if !ok {
				var empty s00.NBIoTPagingDRX
				return empty, fmt.Errorf("binding PagingIEs.id-NB-IoT-PagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldEncode(&sealed) = func(value s00.NBIoTPagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(324), rowNBIoTPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldCapture(&sealed) = func(v s00.NBIoTPagingDRX, options aper.DecodeState) (s00.NBIoTPagingDRX, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldCompare(&sealed) = func(v s00.NBIoTPagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTPagingDRX(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTPagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTPagingDRX) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(324), rowNBIoTPagingDRX: &value}
		}, get: func(value *PagingIEValue) (*s00.NBIoTPagingDRX, bool) { return value.AsNBIoTPagingDRX() }}
}
func (PagingIETable) infoPagingCause() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(331), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingCause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-PagingCause"}}}
}

// PagingCause returns the typed binding for the PagingCause row of PagingIETable.
func (t PagingIETable) PagingCause() PagingPagingCauseIEBinding {
	return PagingPagingCauseIEBinding{info: t.infoPagingCause(), codec: func() s01.PagingCauseValueCodec {
		sealed := s01.PagingCauseValueCodec{}
		*s01.BridgePagingCauseValueCodecFieldPath(&sealed) = "PagingCause"
		*s01.BridgePagingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingCause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingCause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingCause")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(331), raw)
			if err != nil {
				var empty s00.PagingCause
				return empty, runtime.WrapDecodePath(err, "PagingCause")
			}
			value, ok := decoded.AsPagingCause()
			if !ok {
				var empty s00.PagingCause
				return empty, fmt.Errorf("binding PagingIEs.id-PagingCause: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingCauseValueCodecFieldEncode(&sealed) = func(value s00.PagingCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(331), rowPagingCause: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingCauseValueCodecFieldCapture(&sealed) = func(v s00.PagingCause, options aper.DecodeState) (s00.PagingCause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingCause(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingCauseValueCodecFieldCompare(&sealed) = func(v s00.PagingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgePagingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingCause) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(331), rowPagingCause: &value}
		}, get: func(value *PagingIEValue) (*s00.PagingCause, bool) { return value.AsPagingCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PagingIETable.
func (t PagingIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PagingIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(80):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEIdentityIndexValue requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(43):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEPagingID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(44):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-pagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(109):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-CNDomain requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(46):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAIList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(128):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-IdList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(151):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-PagingPriority requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(198):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(211):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-AssistanceDataForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(227):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-Paging-eDRXInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(231):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-extended-UEIdentityIndexValue requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(239):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-Paging-eDRXInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(244):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-UEIdentityIndexValue requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(304):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-DataSize requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(323):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-WUS-Assistance-Information requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(324):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-PagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(331):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-PagingCause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PagingIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PagingIEField{}, aper.OperationError(err, "Opaque")
		}
		return PagingIEField{Id: id, Criticality: criticality, Value: PagingIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AssistanceDataForPagingCodec binds the complete APER value type.
func AssistanceDataForPagingCodec() s26.AssistanceDataForPagingValueCodec {
	return PagingIEs().AssistanceDataForPaging().Codec()
}

// CNDomainCodec binds the complete APER value type.
func CNDomainCodec() s00.CNDomainValueCodec { return PagingIEs().CNDomain().Codec() }

// DataSizeCodec binds the complete APER value type.
func DataSizeCodec() s00.DataSizeValueCodec { return PagingIEs().DataSize().Codec() }

// ExtendedUEIdentityIndexValueCodec binds the complete APER value type.
func ExtendedUEIdentityIndexValueCodec() s00.ExtendedUEIdentityIndexValueValueCodec {
	return PagingIEs().ExtendedUEIdentityIndexValue().Codec()
}

// NBIoTPagingDRXCodec binds the complete APER value type.
func NBIoTPagingDRXCodec() s01.NBIoTPagingDRXValueCodec { return PagingIEs().NBIoTPagingDRX().Codec() }

// NBIoTPagingEDRXInformationCodec binds the complete APER value type.
func NBIoTPagingEDRXInformationCodec() s19.NBIoTPagingEDRXInformationValueCodec {
	return PagingIEs().NBIoTPagingEDRXInformation().Codec()
}

// NBIoTUEIdentityIndexValueCodec binds the complete APER value type.
func NBIoTUEIdentityIndexValueCodec() s01.NBIoTUEIdentityIndexValueValueCodec {
	return PagingIEs().NBIoTUEIdentityIndexValue().Codec()
}

// PagingCauseCodec binds the complete APER value type.
func PagingCauseCodec() s01.PagingCauseValueCodec { return PagingIEs().PagingCause().Codec() }

// PagingEDRXInformationCodec binds the complete APER value type.
func PagingEDRXInformationCodec() s20.PagingEDRXInformationValueCodec {
	return PagingIEs().PagingEDRXInformation().Codec()
}

// PagingPriorityCodec binds the complete APER value type.
func PagingPriorityCodec() s01.PagingPriorityValueCodec { return PagingIEs().PagingPriority().Codec() }

// TAIListCodec binds the complete APER value type.
func TAIListCodec() s34.TAIListValueCodec { return PagingIEs().TAIList().Codec() }

// UEIdentityIndexValueCodec binds the complete APER value type.
func UEIdentityIndexValueCodec() s02.UEIdentityIndexValueValueCodec {
	return PagingIEs().UEIdentityIndexValue().Codec()
}

// UEPagingIDCodec binds the complete APER value type.
func UEPagingIDCodec() s28.UEPagingIDValueCodec { return PagingIEs().UEPagingID().Codec() }

// UERadioCapabilityForPagingCodec binds the complete APER value type.
func UERadioCapabilityForPagingCodec() s02.UERadioCapabilityForPagingValueCodec {
	return PagingIEs().UERadioCapabilityForPaging().Codec()
}

// WUSAssistanceInformationCodec binds the complete APER value type.
func WUSAssistanceInformationCodec() WUSAssistanceInformationValueCodec {
	return PagingIEs().WUSAssistanceInformation().Codec()
}
func BridgeValidateHandoverRequiredBudget(v *s35.HandoverRequired, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequired")
	}
	rows := []s00.FieldInfo{s34.HandoverRequiredIEs().MMEUES1APID().Info(), s34.HandoverRequiredIEs().ENBUES1APID().Info(), s34.HandoverRequiredIEs().HandoverType().Info(), s34.HandoverRequiredIEs().Cause().Info(), s34.HandoverRequiredIEs().TargetID().Info(), s34.HandoverRequiredIEs().DirectForwardingPathAvailability().Info(), s34.HandoverRequiredIEs().SRVCCHOIndication().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainer().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainerSecondary().Info(), s34.HandoverRequiredIEs().MSClassmark2().Info(), s34.HandoverRequiredIEs().MSClassmark3().Info(), s34.HandoverRequiredIEs().CSGId().Info(), s34.HandoverRequiredIEs().CellAccessMode().Info(), s34.HandoverRequiredIEs().PSServiceNotAvailable().Info()}
	report := s35.BridgeHandoverRequiredIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequired.protocolIEs", budget)
	BridgeWalkValidationHandoverRequired(v, &report, "HandoverRequired", true)
	return report, nil
}
func BridgeValidateHandoverCommandBudget(v *s41.HandoverCommand, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverCommand")
	}
	rows := []s00.FieldInfo{s41.HandoverCommandIEs().MMEUES1APID().Info(), s41.HandoverCommandIEs().ENBUES1APID().Info(), s41.HandoverCommandIEs().HandoverType().Info(), s41.HandoverCommandIEs().NASSecurityParametersfromEUTRAN().Info(), s41.HandoverCommandIEs().ERABSubjecttoDataForwardingList().Info(), s41.HandoverCommandIEs().ERABtoReleaseListHOCmd().Info(), s41.HandoverCommandIEs().TargetToSourceTransparentContainer().Info(), s41.HandoverCommandIEs().TargetToSourceTransparentContainerSecondary().Info(), s41.HandoverCommandIEs().CriticalityDiagnostics().Info()}
	report := s41.BridgeHandoverCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverCommand.protocolIEs", budget)
	BridgeWalkValidationHandoverCommand(v, &report, "HandoverCommand", true)
	return report, nil
}
func BridgeValidateHandoverPreparationFailureBudget(v *s25.HandoverPreparationFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverPreparationFailure")
	}
	rows := []s00.FieldInfo{s22.HandoverPreparationFailureIEs().MMEUES1APID().Info(), s22.HandoverPreparationFailureIEs().ENBUES1APID().Info(), s22.HandoverPreparationFailureIEs().Cause().Info(), s22.HandoverPreparationFailureIEs().CriticalityDiagnostics().Info()}
	report := s27.BridgeHandoverPreparationFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverPreparationFailure.protocolIEs", budget)
	BridgeWalkValidationHandoverPreparationFailure(v, &report, "HandoverPreparationFailure", true)
	return report, nil
}
func BridgeValidateHandoverRequestAcknowledgeBudget(v *s39.HandoverRequestAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequestAcknowledge")
	}
	rows := []s00.FieldInfo{s39.HandoverRequestAcknowledgeIEs().MMEUES1APID().Info(), s39.HandoverRequestAcknowledgeIEs().ENBUES1APID().Info(), s39.HandoverRequestAcknowledgeIEs().ERABAdmittedList().Info(), s39.HandoverRequestAcknowledgeIEs().ERABFailedToSetupListHOReqAck().Info(), s39.HandoverRequestAcknowledgeIEs().TargetToSourceTransparentContainer().Info(), s39.HandoverRequestAcknowledgeIEs().CSGId().Info(), s39.HandoverRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s39.HandoverRequestAcknowledgeIEs().CellAccessMode().Info(), s39.HandoverRequestAcknowledgeIEs().CEModeBSupportIndicator().Info()}
	report := s39.BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequestAcknowledge.protocolIEs", budget)
	BridgeWalkValidationHandoverRequestAcknowledge(v, &report, "HandoverRequestAcknowledge", true)
	return report, nil
}
func BridgeValidateHandoverFailureBudget(v *s25.HandoverFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverFailure")
	}
	rows := []s00.FieldInfo{s22.HandoverFailureIEs().MMEUES1APID().Info(), s22.HandoverFailureIEs().Cause().Info(), s22.HandoverFailureIEs().CriticalityDiagnostics().Info()}
	report := s27.BridgeHandoverFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverFailure.protocolIEs", budget)
	BridgeWalkValidationHandoverFailure(v, &report, "HandoverFailure", true)
	return report, nil
}
func BridgeValidateHandoverNotifyBudget(v *s36.HandoverNotify, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverNotify")
	}
	rows := []s00.FieldInfo{s35.HandoverNotifyIEs().MMEUES1APID().Info(), s35.HandoverNotifyIEs().ENBUES1APID().Info(), s35.HandoverNotifyIEs().EUTRANCGI().Info(), s35.HandoverNotifyIEs().TAI().Info(), s35.HandoverNotifyIEs().TunnelInformationForBBF().Info(), s35.HandoverNotifyIEs().LHNID().Info(), s35.HandoverNotifyIEs().PSCellInformation().Info(), s35.HandoverNotifyIEs().NotifySourceeNB().Info(), s35.HandoverNotifyIEs().LTENTNTAIInformation().Info()}
	report := s36.BridgeHandoverNotifyIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverNotify.protocolIEs", budget)
	BridgeWalkValidationHandoverNotify(v, &report, "HandoverNotify", true)
	return report, nil
}
func BridgeValidatePathSwitchRequestFailureBudget(v *s26.PathSwitchRequestFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequestFailure")
	}
	rows := []s00.FieldInfo{s23.PathSwitchRequestFailureIEs().MMEUES1APID().Info(), s23.PathSwitchRequestFailureIEs().ENBUES1APID().Info(), s23.PathSwitchRequestFailureIEs().Cause().Info(), s23.PathSwitchRequestFailureIEs().CriticalityDiagnostics().Info()}
	report := s28.BridgePathSwitchRequestFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequestFailure.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequestFailure(v, &report, "PathSwitchRequestFailure", true)
	return report, nil
}
func BridgeValidateHandoverCancelBudget(v *s25.HandoverCancel, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverCancel")
	}
	rows := []s00.FieldInfo{s18.HandoverCancelIEs().MMEUES1APID().Info(), s18.HandoverCancelIEs().ENBUES1APID().Info(), s18.HandoverCancelIEs().Cause().Info()}
	report := s27.BridgeHandoverCancelIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverCancel.protocolIEs", budget)
	BridgeWalkValidationHandoverCancel(v, &report, "HandoverCancel", true)
	return report, nil
}
func BridgeValidateHandoverCancelAcknowledgeBudget(v *s25.HandoverCancelAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverCancelAcknowledge")
	}
	rows := []s00.FieldInfo{s22.HandoverCancelAcknowledgeIEs().MMEUES1APID().Info(), s22.HandoverCancelAcknowledgeIEs().ENBUES1APID().Info(), s22.HandoverCancelAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s27.BridgeHandoverCancelAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverCancelAcknowledge.protocolIEs", budget)
	BridgeWalkValidationHandoverCancelAcknowledge(v, &report, "HandoverCancelAcknowledge", true)
	return report, nil
}
func BridgeValidateERABSetupRequestBudget(v *s41.ERABSetupRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABSetupRequest")
	}
	rows := []s00.FieldInfo{s41.ERABSetupRequestIEs().MMEUES1APID().Info(), s41.ERABSetupRequestIEs().ENBUES1APID().Info(), s41.ERABSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s41.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Info()}
	report := s41.BridgeERABSetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABSetupRequest.protocolIEs", budget)
	BridgeWalkValidationERABSetupRequest(v, &report, "ERABSetupRequest", true)
	return report, nil
}
func BridgeValidateERABModifyRequestBudget(v *s41.ERABModifyRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModifyRequest")
	}
	rows := []s00.FieldInfo{s41.ERABModifyRequestIEs().MMEUES1APID().Info(), s41.ERABModifyRequestIEs().ENBUES1APID().Info(), s41.ERABModifyRequestIEs().UEaggregateMaximumBitrate().Info(), s41.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Info(), s41.ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Info()}
	report := s41.BridgeERABModifyRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModifyRequest.protocolIEs", budget)
	BridgeWalkValidationERABModifyRequest(v, &report, "ERABModifyRequest", true)
	return report, nil
}
func BridgeValidateERABReleaseCommandBudget(v *s40.ERABReleaseCommand, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseCommand")
	}
	rows := []s00.FieldInfo{s40.ERABReleaseCommandIEs().MMEUES1APID().Info(), s40.ERABReleaseCommandIEs().ENBUES1APID().Info(), s40.ERABReleaseCommandIEs().UEaggregateMaximumBitrate().Info(), s40.ERABReleaseCommandIEs().ERABToBeReleasedList().Info(), s40.ERABReleaseCommandIEs().NASPDU().Info()}
	report := s40.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseCommand.protocolIEs", budget)
	BridgeWalkValidationERABReleaseCommand(v, &report, "ERABReleaseCommand", true)
	return report, nil
}
func BridgeValidateInitialContextSetupResponseBudget(v *s40.InitialContextSetupResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialContextSetupResponse")
	}
	rows := []s00.FieldInfo{s40.InitialContextSetupResponseIEs().MMEUES1APID().Info(), s40.InitialContextSetupResponseIEs().ENBUES1APID().Info(), s40.InitialContextSetupResponseIEs().ERABSetupListCtxtSURes().Info(), s40.InitialContextSetupResponseIEs().ERABFailedToSetupListCtxtSURes().Info(), s40.InitialContextSetupResponseIEs().CriticalityDiagnostics().Info()}
	report := s40.BridgeInitialContextSetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupResponse.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupResponse(v, &report, "InitialContextSetupResponse", true)
	return report, nil
}
func BridgeValidateInitialContextSetupFailureBudget(v *s25.InitialContextSetupFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialContextSetupFailure")
	}
	rows := []s00.FieldInfo{s23.InitialContextSetupFailureIEs().MMEUES1APID().Info(), s23.InitialContextSetupFailureIEs().ENBUES1APID().Info(), s23.InitialContextSetupFailureIEs().Cause().Info(), s23.InitialContextSetupFailureIEs().CriticalityDiagnostics().Info()}
	report := s27.BridgeInitialContextSetupFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupFailure.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupFailure(v, &report, "InitialContextSetupFailure", true)
	return report, nil
}
func BridgeValidateDownlinkNASTransportBudget(v *s43.DownlinkNASTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkNASTransport")
	}
	rows := []s00.FieldInfo{s43.DownlinkNASTransportIEs().MMEUES1APID().Info(), s43.DownlinkNASTransportIEs().ENBUES1APID().Info(), s43.DownlinkNASTransportIEs().NASPDU().Info(), s43.DownlinkNASTransportIEs().HandoverRestrictionList().Info(), s43.DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Info(), s43.DownlinkNASTransportIEs().SRVCCOperationPossible().Info(), s43.DownlinkNASTransportIEs().UERadioCapability().Info(), s43.DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Info(), s43.DownlinkNASTransportIEs().EnhancedCoverageRestricted().Info(), s43.DownlinkNASTransportIEs().NRUESecurityCapabilities().Info(), s43.DownlinkNASTransportIEs().CEModeBRestricted().Info(), s43.DownlinkNASTransportIEs().UECapabilityInfoRequest().Info(), s43.DownlinkNASTransportIEs().EndIndication().Info(), s43.DownlinkNASTransportIEs().PendingDataIndication().Info(), s43.DownlinkNASTransportIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s43.DownlinkNASTransportIEs().AdditionalRRMPriorityIndex().Info(), s43.DownlinkNASTransportIEs().UERadioCapabilityID().Info(), s43.DownlinkNASTransportIEs().MaskedIMEISV().Info(), s43.DownlinkNASTransportIEs().CoarseUELocation().Info()}
	report := s43.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkNASTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkNASTransport(v, &report, "DownlinkNASTransport", true)
	return report, nil
}
func BridgeValidateInitialUEMessageBudget(v *s36.InitialUEMessage, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialUEMessage")
	}
	rows := []s00.FieldInfo{s36.InitialUEMessageIEs().ENBUES1APID().Info(), s36.InitialUEMessageIEs().NASPDU().Info(), s36.InitialUEMessageIEs().TAI().Info(), s36.InitialUEMessageIEs().EUTRANCGI().Info(), s36.InitialUEMessageIEs().RRCEstablishmentCause().Info(), s36.InitialUEMessageIEs().STMSI().Info(), s36.InitialUEMessageIEs().CSGId().Info(), s36.InitialUEMessageIEs().GUMMEIID().Info(), s36.InitialUEMessageIEs().CellAccessMode().Info(), s36.InitialUEMessageIEs().GWTransportLayerAddress().Info(), s36.InitialUEMessageIEs().RelayNodeIndicator().Info(), s36.InitialUEMessageIEs().GUMMEIType().Info(), s36.InitialUEMessageIEs().TunnelInformationForBBF().Info(), s36.InitialUEMessageIEs().SIPTOLGWTransportLayerAddress().Info(), s36.InitialUEMessageIEs().LHNID().Info(), s36.InitialUEMessageIEs().MMEGroupID().Info(), s36.InitialUEMessageIEs().UEUsageType().Info(), s36.InitialUEMessageIEs().CEModeBSupportIndicator().Info(), s36.InitialUEMessageIEs().DCNID().Info(), s36.InitialUEMessageIEs().CoverageLevel().Info(), s36.InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Info(), s36.InitialUEMessageIEs().EDTSession().Info(), s36.InitialUEMessageIEs().IABNodeIndication().Info(), s36.InitialUEMessageIEs().LTENTNTAIInformation().Info(), s36.InitialUEMessageIEs().CoarseUELocationRequested().Info()}
	report := s36.BridgeInitialUEMessageIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialUEMessage.protocolIEs", budget)
	BridgeWalkValidationInitialUEMessage(v, &report, "InitialUEMessage", true)
	return report, nil
}
func BridgeValidateErrorIndicationBudget(v *s28.ErrorIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ErrorIndication")
	}
	rows := []s00.FieldInfo{s28.ErrorIndicationIEs().MMEUES1APID().Info(), s28.ErrorIndicationIEs().ENBUES1APID().Info(), s28.ErrorIndicationIEs().Cause().Info(), s28.ErrorIndicationIEs().CriticalityDiagnostics().Info(), s28.ErrorIndicationIEs().STMSI().Info()}
	report := s28.BridgeErrorIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ErrorIndication.protocolIEs", budget)
	BridgeWalkValidationErrorIndication(v, &report, "ErrorIndication", true)
	return report, nil
}
func BridgeValidateNASNonDeliveryIndicationBudget(v *s26.NASNonDeliveryIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil NASNonDeliveryIndication")
	}
	rows := []s00.FieldInfo{s19.NASNonDeliveryIndicationIEs().MMEUES1APID().Info(), s19.NASNonDeliveryIndicationIEs().ENBUES1APID().Info(), s19.NASNonDeliveryIndicationIEs().NASPDU().Info(), s19.NASNonDeliveryIndicationIEs().Cause().Info()}
	report := s28.BridgeNASNonDeliveryIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "NASNonDeliveryIndication.protocolIEs", budget)
	BridgeWalkValidationNASNonDeliveryIndication(v, &report, "NASNonDeliveryIndication", true)
	return report, nil
}
func BridgeValidateS1SetupRequestBudget(v *s44.S1SetupRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupRequest")
	}
	rows := []s00.FieldInfo{s44.S1SetupRequestIEs().GlobalENBID().Info(), s44.S1SetupRequestIEs().ENBname().Info(), s44.S1SetupRequestIEs().SupportedTAs().Info(), s44.S1SetupRequestIEs().DefaultPagingDRX().Info(), s44.S1SetupRequestIEs().CSGIdList().Info(), s44.S1SetupRequestIEs().UERetentionInformation().Info(), s44.S1SetupRequestIEs().NBIoTDefaultPagingDRX().Info(), s44.S1SetupRequestIEs().ConnectedengNBList().Info()}
	report := s44.BridgeS1SetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupRequest.protocolIEs", budget)
	BridgeWalkValidationS1SetupRequest(v, &report, "S1SetupRequest", true)
	return report, nil
}
func BridgeValidateS1SetupResponseBudget(v *s44.S1SetupResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupResponse")
	}
	rows := []s00.FieldInfo{s44.S1SetupResponseIEs().MMEname().Info(), s44.S1SetupResponseIEs().ServedGUMMEIs().Info(), s44.S1SetupResponseIEs().RelativeMMECapacity().Info(), s44.S1SetupResponseIEs().MMERelaySupportIndicator().Info(), s44.S1SetupResponseIEs().CriticalityDiagnostics().Info(), s44.S1SetupResponseIEs().UERetentionInformation().Info(), s44.S1SetupResponseIEs().ServedDCNs().Info(), s44.S1SetupResponseIEs().IABSupported().Info()}
	report := s44.BridgeS1SetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupResponse.protocolIEs", budget)
	BridgeWalkValidationS1SetupResponse(v, &report, "S1SetupResponse", true)
	return report, nil
}
func BridgeValidateS1SetupFailureBudget(v *s27.S1SetupFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupFailure")
	}
	rows := []s00.FieldInfo{s23.S1SetupFailureIEs().Cause().Info(), s23.S1SetupFailureIEs().TimeToWait().Info(), s23.S1SetupFailureIEs().CriticalityDiagnostics().Info()}
	report := s28.BridgeS1SetupFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupFailure.protocolIEs", budget)
	BridgeWalkValidationS1SetupFailure(v, &report, "S1SetupFailure", true)
	return report, nil
}
func BridgeValidateDownlinkS1cdma2000tunnellingBudget(v *s41.DownlinkS1cdma2000tunnelling, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkS1cdma2000tunnelling")
	}
	rows := []s00.FieldInfo{s40.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s40.DownlinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s40.DownlinkS1cdma2000tunnellingIEs().ERABSubjecttoDataForwardingList().Info(), s40.DownlinkS1cdma2000tunnellingIEs().Cdma2000HOStatus().Info(), s40.DownlinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s40.DownlinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info()}
	report := s41.BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkS1cdma2000tunnelling.protocolIEs", budget)
	BridgeWalkValidationDownlinkS1cdma2000tunnelling(v, &report, "DownlinkS1cdma2000tunnelling", true)
	return report, nil
}
func BridgeValidateENBStatusTransferBudget(v *s24.ENBStatusTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBStatusTransfer")
	}
	rows := []s00.FieldInfo{s22.ENBStatusTransferIEs().MMEUES1APID().Info(), s22.ENBStatusTransferIEs().ENBUES1APID().Info(), s22.ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
	report := s27.BridgeENBStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationENBStatusTransfer(v, &report, "ENBStatusTransfer", true)
	return report, nil
}
func BridgeValidateMMEStatusTransferBudget(v *s26.MMEStatusTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEStatusTransfer")
	}
	rows := []s00.FieldInfo{s22.MMEStatusTransferIEs().MMEUES1APID().Info(), s22.MMEStatusTransferIEs().ENBUES1APID().Info(), s22.MMEStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
	report := s28.BridgeMMEStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEStatusTransfer(v, &report, "MMEStatusTransfer", true)
	return report, nil
}
func BridgeValidateDeactivateTraceBudget(v *s15.DeactivateTrace, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DeactivateTrace")
	}
	rows := []s00.FieldInfo{s08.DeactivateTraceIEs().MMEUES1APID().Info(), s08.DeactivateTraceIEs().ENBUES1APID().Info(), s08.DeactivateTraceIEs().EUTRANTraceID().Info()}
	report := s27.BridgeDeactivateTraceIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DeactivateTrace.protocolIEs", budget)
	BridgeWalkValidationDeactivateTrace(v, &report, "DeactivateTrace", true)
	return report, nil
}
func BridgeValidateTraceFailureIndicationBudget(v *s35.TraceFailureIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil TraceFailureIndication")
	}
	rows := []s00.FieldInfo{s21.TraceFailureIndicationIEs().MMEUES1APID().Info(), s21.TraceFailureIndicationIEs().ENBUES1APID().Info(), s21.TraceFailureIndicationIEs().EUTRANTraceID().Info(), s21.TraceFailureIndicationIEs().Cause().Info()}
	report := s35.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "TraceFailureIndication.protocolIEs", budget)
	BridgeWalkValidationTraceFailureIndication(v, &report, "TraceFailureIndication", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateBudget(v *s44.ENBConfigurationUpdate, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdate")
	}
	rows := []s00.FieldInfo{s44.ENBConfigurationUpdateIEs().ENBname().Info(), s44.ENBConfigurationUpdateIEs().SupportedTAs().Info(), s44.ENBConfigurationUpdateIEs().CSGIdList().Info(), s44.ENBConfigurationUpdateIEs().DefaultPagingDRX().Info(), s44.ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Info(), s44.ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Info(), s44.ENBConfigurationUpdateIEs().ConnectedengNBToRemoveList().Info()}
	report := s44.BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdate.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdate(v, &report, "ENBConfigurationUpdate", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateAcknowledgeBudget(v *s24.ENBConfigurationUpdateAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdateAcknowledge")
	}
	rows := []s00.FieldInfo{s22.ENBConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s27.BridgeENBConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdateAcknowledge.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdateAcknowledge(v, &report, "ENBConfigurationUpdateAcknowledge", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateFailureBudget(v *s24.ENBConfigurationUpdateFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdateFailure")
	}
	rows := []s00.FieldInfo{s22.ENBConfigurationUpdateFailureIEs().Cause().Info(), s22.ENBConfigurationUpdateFailureIEs().TimeToWait().Info(), s22.ENBConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
	report := s27.BridgeENBConfigurationUpdateFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdateFailure.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdateFailure(v, &report, "ENBConfigurationUpdateFailure", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateBudget(v *s44.MMEConfigurationUpdate, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdate")
	}
	rows := []s00.FieldInfo{s44.MMEConfigurationUpdateIEs().MMEname().Info(), s44.MMEConfigurationUpdateIEs().ServedGUMMEIs().Info(), s44.MMEConfigurationUpdateIEs().RelativeMMECapacity().Info(), s44.MMEConfigurationUpdateIEs().ServedDCNs().Info()}
	report := s44.BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdate.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdate(v, &report, "MMEConfigurationUpdate", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(v *s25.MMEConfigurationUpdateAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdateAcknowledge")
	}
	rows := []s00.FieldInfo{s23.MMEConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s28.BridgeMMEConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdateAcknowledge.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdateAcknowledge(v, &report, "MMEConfigurationUpdateAcknowledge", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateFailureBudget(v *s26.MMEConfigurationUpdateFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdateFailure")
	}
	rows := []s00.FieldInfo{s23.MMEConfigurationUpdateFailureIEs().Cause().Info(), s23.MMEConfigurationUpdateFailureIEs().TimeToWait().Info(), s23.MMEConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
	report := s28.BridgeMMEConfigurationUpdateFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdateFailure.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdateFailure(v, &report, "MMEConfigurationUpdateFailure", true)
	return report, nil
}
func BridgeValidateLocationReportingControlBudget(v *s26.LocationReportingControl, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReportingControl")
	}
	rows := []s00.FieldInfo{s26.LocationReportingControlIEs().MMEUES1APID().Info(), s26.LocationReportingControlIEs().ENBUES1APID().Info(), s26.LocationReportingControlIEs().RequestType().Info()}
	report := s28.BridgeLocationReportingControlIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReportingControl.protocolIEs", budget)
	BridgeWalkValidationLocationReportingControl(v, &report, "LocationReportingControl", true)
	return report, nil
}
func BridgeValidateLocationReportingFailureIndicationBudget(v *s25.LocationReportingFailureIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReportingFailureIndication")
	}
	rows := []s00.FieldInfo{s19.LocationReportingFailureIndicationIEs().MMEUES1APID().Info(), s19.LocationReportingFailureIndicationIEs().ENBUES1APID().Info(), s19.LocationReportingFailureIndicationIEs().Cause().Info()}
	report := s28.BridgeLocationReportingFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReportingFailureIndication.protocolIEs", budget)
	BridgeWalkValidationLocationReportingFailureIndication(v, &report, "LocationReportingFailureIndication", true)
	return report, nil
}
func BridgeValidateLocationReportBudget(v *s33.LocationReport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReport")
	}
	rows := []s00.FieldInfo{s32.LocationReportIEs().MMEUES1APID().Info(), s32.LocationReportIEs().ENBUES1APID().Info(), s32.LocationReportIEs().EUTRANCGI().Info(), s32.LocationReportIEs().TAI().Info(), s32.LocationReportIEs().RequestType().Info(), s32.LocationReportIEs().PSCellInformation().Info(), s32.LocationReportIEs().LTENTNTAIInformation().Info()}
	report := s33.BridgeLocationReportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReport.protocolIEs", budget)
	BridgeWalkValidationLocationReport(v, &report, "LocationReport", true)
	return report, nil
}
func BridgeValidateOverloadStartBudget(v *s42.OverloadStart, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OverloadStart")
	}
	rows := []s00.FieldInfo{s42.OverloadStartIEs().OverloadResponse().Info(), s42.OverloadStartIEs().GUMMEIList().Info(), s42.OverloadStartIEs().TrafficLoadReductionIndication().Info()}
	report := s42.BridgeOverloadStartIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "OverloadStart.protocolIEs", budget)
	BridgeWalkValidationOverloadStart(v, &report, "OverloadStart", true)
	return report, nil
}
func BridgeValidateOverloadStopBudget(v *s42.OverloadStop, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OverloadStop")
	}
	rows := []s00.FieldInfo{s42.OverloadStopIEs().GUMMEIList().Info()}
	report := s42.BridgeOverloadStopIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "OverloadStop.protocolIEs", budget)
	BridgeWalkValidationOverloadStop(v, &report, "OverloadStop", true)
	return report, nil
}
func BridgeValidateENBDirectInformationTransferBudget(v *s34.ENBDirectInformationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBDirectInformationTransfer")
	}
	rows := []s00.FieldInfo{s34.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Info()}
	report := s34.BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBDirectInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationENBDirectInformationTransfer(v, &report, "ENBDirectInformationTransfer", true)
	return report, nil
}
func BridgeValidateMMEDirectInformationTransferBudget(v *s34.MMEDirectInformationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEDirectInformationTransfer")
	}
	rows := []s00.FieldInfo{s34.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().Info()}
	report := s34.BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEDirectInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEDirectInformationTransfer(v, &report, "MMEDirectInformationTransfer", true)
	return report, nil
}
func BridgeValidateCellTrafficTraceBudget(v *s21.CellTrafficTrace, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil CellTrafficTrace")
	}
	rows := []s00.FieldInfo{s18.CellTrafficTraceIEs().MMEUES1APID().Info(), s18.CellTrafficTraceIEs().ENBUES1APID().Info(), s18.CellTrafficTraceIEs().EUTRANTraceID().Info(), s18.CellTrafficTraceIEs().EUTRANCGI().Info(), s18.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().Info(), s18.CellTrafficTraceIEs().PrivacyIndicator().Info()}
	report := s27.BridgeCellTrafficTraceIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "CellTrafficTrace.protocolIEs", budget)
	BridgeWalkValidationCellTrafficTrace(v, &report, "CellTrafficTrace", true)
	return report, nil
}
func BridgeValidateKillResponseBudget(v *s33.KillResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil KillResponse")
	}
	rows := []s00.FieldInfo{s33.KillResponseIEs().MessageIdentifier().Info(), s33.KillResponseIEs().SerialNumber().Info(), s33.KillResponseIEs().BroadcastCancelledAreaList().Info(), s33.KillResponseIEs().CriticalityDiagnostics().Info()}
	report := s33.BridgeKillResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "KillResponse.protocolIEs", budget)
	BridgeWalkValidationKillResponse(v, &report, "KillResponse", true)
	return report, nil
}
func BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(v *s15.DownlinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s08.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s08.DownlinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s08.DownlinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s08.DownlinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s27.BridgeDownlinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkUEAssociatedLPPaTransport(v, &report, "DownlinkUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(v *s15.DownlinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkNonUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s08.DownlinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s08.DownlinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s27.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkNonUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkNonUEAssociatedLPPaTransport(v, &report, "DownlinkNonUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidatePWSRestartIndicationBudget(v *s44.PWSRestartIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PWSRestartIndication")
	}
	rows := []s00.FieldInfo{s44.PWSRestartIndicationIEs().ECGIListForRestart().Info(), s44.PWSRestartIndicationIEs().GlobalENBID().Info(), s44.PWSRestartIndicationIEs().TAIListForRestart().Info(), s44.PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Info()}
	report := s45.BridgePWSRestartIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PWSRestartIndication.protocolIEs", budget)
	BridgeWalkValidationPWSRestartIndication(v, &report, "PWSRestartIndication", true)
	return report, nil
}
func BridgeValidateERABModificationConfirmBudget(v *s40.ERABModificationConfirm, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModificationConfirm")
	}
	rows := []s00.FieldInfo{s40.ERABModificationConfirmIEs().MMEUES1APID().Info(), s40.ERABModificationConfirmIEs().ENBUES1APID().Info(), s40.ERABModificationConfirmIEs().ERABModifyListBearerModConf().Info(), s40.ERABModificationConfirmIEs().ERABFailedToModifyListBearerModConf().Info(), s40.ERABModificationConfirmIEs().ERABToBeReleasedListBearerModConf().Info(), s40.ERABModificationConfirmIEs().CriticalityDiagnostics().Info(), s40.ERABModificationConfirmIEs().CSGMembershipStatus().Info()}
	report := s40.BridgeERABModificationConfirmIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModificationConfirm.protocolIEs", budget)
	BridgeWalkValidationERABModificationConfirm(v, &report, "ERABModificationConfirm", true)
	return report, nil
}
func BridgeValidatePWSFailureIndicationBudget(v *s43.PWSFailureIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PWSFailureIndication")
	}
	rows := []s00.FieldInfo{s43.PWSFailureIndicationIEs().PWSfailedECGIList().Info(), s43.PWSFailureIndicationIEs().GlobalENBID().Info()}
	report := s43.BridgePWSFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PWSFailureIndication.protocolIEs", budget)
	BridgeWalkValidationPWSFailureIndication(v, &report, "PWSFailureIndication", true)
	return report, nil
}
func BridgeValidateRerouteNASRequestBudget(v *s27.RerouteNASRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil RerouteNASRequest")
	}
	rows := []s00.FieldInfo{s20.RerouteNASRequestIEs().ENBUES1APID().Info(), s20.RerouteNASRequestIEs().MMEUES1APID().Info(), s20.RerouteNASRequestIEs().S1Message().Info(), s20.RerouteNASRequestIEs().MMEGroupID().Info(), s20.RerouteNASRequestIEs().AdditionalGUTI().Info(), s20.RerouteNASRequestIEs().UEUsageType().Info()}
	report := s28.BridgeRerouteNASRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "RerouteNASRequest.protocolIEs", budget)
	BridgeWalkValidationRerouteNASRequest(v, &report, "RerouteNASRequest", true)
	return report, nil
}
func BridgeValidateConnectionEstablishmentIndicationBudget(v *s31.ConnectionEstablishmentIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ConnectionEstablishmentIndication")
	}
	rows := []s00.FieldInfo{s31.ConnectionEstablishmentIndicationIEs().MMEUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().ENBUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapability().Info(), s31.ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Info(), s31.ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().EndIndication().Info(), s31.ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Info(), s31.ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Info(), s31.ConnectionEstablishmentIndicationIEs().CoarseUELocation().Info()}
	report := s31.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ConnectionEstablishmentIndication.protocolIEs", budget)
	BridgeWalkValidationConnectionEstablishmentIndication(v, &report, "ConnectionEstablishmentIndication", true)
	return report, nil
}
func BridgeValidateNASDeliveryIndicationBudget(v *s19.NASDeliveryIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil NASDeliveryIndication")
	}
	rows := []s00.FieldInfo{s10.NASDeliveryIndicationIEs().MMEUES1APID().Info(), s10.NASDeliveryIndicationIEs().ENBUES1APID().Info()}
	report := s28.BridgeNASDeliveryIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "NASDeliveryIndication.protocolIEs", budget)
	BridgeWalkValidationNASDeliveryIndication(v, &report, "NASDeliveryIndication", true)
	return report, nil
}
func BridgeValidateRetrieveUEInformationBudget(v *s28.RetrieveUEInformation, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil RetrieveUEInformation")
	}
	rows := []s00.FieldInfo{s28.RetrieveUEInformationIEs().STMSI().Info()}
	report := s28.BridgeRetrieveUEInformationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "RetrieveUEInformation.protocolIEs", budget)
	BridgeWalkValidationRetrieveUEInformation(v, &report, "RetrieveUEInformation", true)
	return report, nil
}
func BridgeValidateMMECPRelocationIndicationBudget(v *s19.MMECPRelocationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMECPRelocationIndication")
	}
	rows := []s00.FieldInfo{s10.MMECPRelocationIndicationIEs().MMEUES1APID().Info(), s10.MMECPRelocationIndicationIEs().ENBUES1APID().Info()}
	report := s28.BridgeMMECPRelocationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMECPRelocationIndication.protocolIEs", budget)
	BridgeWalkValidationMMECPRelocationIndication(v, &report, "MMECPRelocationIndication", true)
	return report, nil
}
func BridgeValidateHandoverSuccessBudget(v *s18.HandoverSuccess, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverSuccess")
	}
	rows := []s00.FieldInfo{s09.HandoverSuccessIEs().MMEUES1APID().Info(), s09.HandoverSuccessIEs().ENBUES1APID().Info()}
	report := s27.BridgeHandoverSuccessIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverSuccess.protocolIEs", budget)
	BridgeWalkValidationHandoverSuccess(v, &report, "HandoverSuccess", true)
	return report, nil
}
func BridgeValidateENBEarlyStatusTransferBudget(v *s38.ENBEarlyStatusTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBEarlyStatusTransfer")
	}
	rows := []s00.FieldInfo{s38.ENBEarlyStatusTransferIEs().MMEUES1APID().Info(), s38.ENBEarlyStatusTransferIEs().ENBUES1APID().Info(), s38.ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
	report := s38.BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBEarlyStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationENBEarlyStatusTransfer(v, &report, "ENBEarlyStatusTransfer", true)
	return report, nil
}
func BridgeValidateMMEEarlyStatusTransferBudget(v *s38.MMEEarlyStatusTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEEarlyStatusTransfer")
	}
	rows := []s00.FieldInfo{s38.MMEEarlyStatusTransferIEs().MMEUES1APID().Info(), s38.MMEEarlyStatusTransferIEs().ENBUES1APID().Info(), s38.MMEEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
	report := s38.BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEEarlyStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEEarlyStatusTransfer(v, &report, "MMEEarlyStatusTransfer", true)
	return report, nil
}
func BridgeValidateS1RemovalRequestBudget(v *s27.S1RemovalRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1RemovalRequest")
	}
	rows := []s00.FieldInfo{s20.S1RemovalRequestIEs().GlobalENBID().Info()}
	report := s28.BridgeS1RemovalRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1RemovalRequest.protocolIEs", budget)
	BridgeWalkValidationS1RemovalRequest(v, &report, "S1RemovalRequest", true)
	return report, nil
}
func BridgeValidateS1RemovalResponseBudget(v *s27.S1RemovalResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1RemovalResponse")
	}
	rows := []s00.FieldInfo{s23.S1RemovalResponseIEs().MMEname().Info(), s23.S1RemovalResponseIEs().CriticalityDiagnostics().Info()}
	report := s28.BridgeS1RemovalResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1RemovalResponse.protocolIEs", budget)
	BridgeWalkValidationS1RemovalResponse(v, &report, "S1RemovalResponse", true)
	return report, nil
}
func BridgeValidateS1RemovalFailureBudget(v *s27.S1RemovalFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1RemovalFailure")
	}
	rows := []s00.FieldInfo{s23.S1RemovalFailureIEs().Cause().Info(), s23.S1RemovalFailureIEs().CriticalityDiagnostics().Info()}
	report := s28.BridgeS1RemovalFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1RemovalFailure.protocolIEs", budget)
	BridgeWalkValidationS1RemovalFailure(v, &report, "S1RemovalFailure", true)
	return report, nil
}
func ValidateHandoverRequired(v *s35.HandoverRequired, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverRequired")
	}
	report, err := BridgeValidateHandoverRequiredBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s35.BridgeHandoverRequiredMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequired")
}
func ValidateHandoverCommand(v *s41.HandoverCommand, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverCommand")
	}
	report, err := BridgeValidateHandoverCommandBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s41.BridgeHandoverCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverCommand")
}
func ValidateHandoverPreparationFailure(v *s25.HandoverPreparationFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	report, err := BridgeValidateHandoverPreparationFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverPreparationFailure")
}
func ValidateHandoverRequestAcknowledge(v *s39.HandoverRequestAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	report, err := BridgeValidateHandoverRequestAcknowledgeBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s39.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequestAcknowledge")
}
func ValidateHandoverFailure(v *s25.HandoverFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverFailure")
	}
	report, err := BridgeValidateHandoverFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeHandoverFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverFailure")
}
func ValidateHandoverNotify(v *s36.HandoverNotify, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverNotify")
	}
	report, err := BridgeValidateHandoverNotifyBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeHandoverNotifyMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverNotify")
}
func ValidatePathSwitchRequestFailure(v *s26.PathSwitchRequestFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	report, err := BridgeValidatePathSwitchRequestFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s26.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequestFailure")
}
func ValidateHandoverCancel(v *s25.HandoverCancel, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverCancel")
	}
	report, err := BridgeValidateHandoverCancelBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeHandoverCancelMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverCancel")
}
func ValidateHandoverCancelAcknowledge(v *s25.HandoverCancelAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	report, err := BridgeValidateHandoverCancelAcknowledgeBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverCancelAcknowledge")
}
func ValidateERABSetupRequest(v *s41.ERABSetupRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABSetupRequest")
	}
	report, err := BridgeValidateERABSetupRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s41.BridgeERABSetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABSetupRequest")
}
func ValidateERABModifyRequest(v *s41.ERABModifyRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModifyRequest")
	}
	report, err := BridgeValidateERABModifyRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s41.BridgeERABModifyRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModifyRequest")
}
func ValidateERABReleaseCommand(v *s40.ERABReleaseCommand, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	report, err := BridgeValidateERABReleaseCommandBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s40.BridgeERABReleaseCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseCommand")
}
func ValidateInitialContextSetupResponse(v *s40.InitialContextSetupResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	report, err := BridgeValidateInitialContextSetupResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s40.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupResponse")
}
func ValidateInitialContextSetupFailure(v *s25.InitialContextSetupFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	report, err := BridgeValidateInitialContextSetupFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupFailure")
}
func ValidateDownlinkNASTransport(v *s43.DownlinkNASTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	report, err := BridgeValidateDownlinkNASTransportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeDownlinkNASTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkNASTransport")
}
func ValidateInitialUEMessage(v *s36.InitialUEMessage, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "InitialUEMessage")
	}
	report, err := BridgeValidateInitialUEMessageBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeInitialUEMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialUEMessage")
}
func ValidateErrorIndication(v *s28.ErrorIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ErrorIndication")
	}
	report, err := BridgeValidateErrorIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s28.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ErrorIndication")
}
func ValidateNASNonDeliveryIndication(v *s26.NASNonDeliveryIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	report, err := BridgeValidateNASNonDeliveryIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s26.BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "NASNonDeliveryIndication")
}
func ValidateS1SetupRequest(v *s44.S1SetupRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1SetupRequest")
	}
	report, err := BridgeValidateS1SetupRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeS1SetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupRequest")
}
func ValidateS1SetupResponse(v *s44.S1SetupResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1SetupResponse")
	}
	report, err := BridgeValidateS1SetupResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeS1SetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupResponse")
}
func ValidateS1SetupFailure(v *s27.S1SetupFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1SetupFailure")
	}
	report, err := BridgeValidateS1SetupFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s27.BridgeS1SetupFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupFailure")
}
func ValidateDownlinkS1cdma2000tunnelling(v *s41.DownlinkS1cdma2000tunnelling, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	report, err := BridgeValidateDownlinkS1cdma2000tunnellingBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s41.BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
}
func ValidateENBStatusTransfer(v *s24.ENBStatusTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	report, err := BridgeValidateENBStatusTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s24.BridgeENBStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBStatusTransfer")
}
func ValidateMMEStatusTransfer(v *s26.MMEStatusTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	report, err := BridgeValidateMMEStatusTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s26.BridgeMMEStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEStatusTransfer")
}
func ValidateDeactivateTrace(v *s15.DeactivateTrace, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "DeactivateTrace")
	}
	report, err := BridgeValidateDeactivateTraceBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s15.BridgeDeactivateTraceMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DeactivateTrace")
}
func ValidateTraceFailureIndication(v *s35.TraceFailureIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "TraceFailureIndication")
	}
	report, err := BridgeValidateTraceFailureIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s35.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceFailureIndication")
}
func ValidateENBConfigurationUpdate(v *s44.ENBConfigurationUpdate, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	report, err := BridgeValidateENBConfigurationUpdateBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdate")
}
func ValidateENBConfigurationUpdateAcknowledge(v *s24.ENBConfigurationUpdateAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	report, err := BridgeValidateENBConfigurationUpdateAcknowledgeBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s24.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func ValidateENBConfigurationUpdateFailure(v *s24.ENBConfigurationUpdateFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	report, err := BridgeValidateENBConfigurationUpdateFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s24.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdateFailure")
}
func ValidateMMEConfigurationUpdate(v *s44.MMEConfigurationUpdate, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	report, err := BridgeValidateMMEConfigurationUpdateBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdate")
}
func ValidateMMEConfigurationUpdateAcknowledge(v *s25.MMEConfigurationUpdateAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	report, err := BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
}
func ValidateMMEConfigurationUpdateFailure(v *s26.MMEConfigurationUpdateFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	report, err := BridgeValidateMMEConfigurationUpdateFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s26.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdateFailure")
}
func ValidateLocationReportingControl(v *s26.LocationReportingControl, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "LocationReportingControl")
	}
	report, err := BridgeValidateLocationReportingControlBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s26.BridgeLocationReportingControlMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReportingControl")
}
func ValidateLocationReportingFailureIndication(v *s25.LocationReportingFailureIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	report, err := BridgeValidateLocationReportingFailureIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReportingFailureIndication")
}
func ValidateLocationReport(v *s33.LocationReport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "LocationReport")
	}
	report, err := BridgeValidateLocationReportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s33.BridgeLocationReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReport")
}
func ValidateOverloadStart(v *s42.OverloadStart, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "OverloadStart")
	}
	report, err := BridgeValidateOverloadStartBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s42.BridgeOverloadStartMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OverloadStart")
}
func ValidateOverloadStop(v *s42.OverloadStop, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "OverloadStop")
	}
	report, err := BridgeValidateOverloadStopBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s42.BridgeOverloadStopMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OverloadStop")
}
func ValidateENBDirectInformationTransfer(v *s34.ENBDirectInformationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	report, err := BridgeValidateENBDirectInformationTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s34.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBDirectInformationTransfer")
}
func ValidateMMEDirectInformationTransfer(v *s34.MMEDirectInformationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	report, err := BridgeValidateMMEDirectInformationTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s34.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEDirectInformationTransfer")
}
func ValidateCellTrafficTrace(v *s21.CellTrafficTrace, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "CellTrafficTrace")
	}
	report, err := BridgeValidateCellTrafficTraceBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s21.BridgeCellTrafficTraceMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "CellTrafficTrace")
}
func ValidateKillResponse(v *s33.KillResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "KillResponse")
	}
	report, err := BridgeValidateKillResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s33.BridgeKillResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "KillResponse")
}
func ValidateDownlinkUEAssociatedLPPaTransport(v *s15.DownlinkUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s15.BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
}
func ValidateDownlinkNonUEAssociatedLPPaTransport(v *s15.DownlinkNonUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s15.BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
}
func ValidatePWSRestartIndication(v *s44.PWSRestartIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PWSRestartIndication")
	}
	report, err := BridgeValidatePWSRestartIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgePWSRestartIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PWSRestartIndication")
}
func ValidateERABModificationConfirm(v *s40.ERABModificationConfirm, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	report, err := BridgeValidateERABModificationConfirmBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s40.BridgeERABModificationConfirmMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModificationConfirm")
}
func ValidatePWSFailureIndication(v *s43.PWSFailureIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PWSFailureIndication")
	}
	report, err := BridgeValidatePWSFailureIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgePWSFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PWSFailureIndication")
}
func ValidateRerouteNASRequest(v *s27.RerouteNASRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "RerouteNASRequest")
	}
	report, err := BridgeValidateRerouteNASRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s27.BridgeRerouteNASRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "RerouteNASRequest")
}
func ValidateConnectionEstablishmentIndication(v *s31.ConnectionEstablishmentIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	report, err := BridgeValidateConnectionEstablishmentIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func ValidateNASDeliveryIndication(v *s19.NASDeliveryIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	report, err := BridgeValidateNASDeliveryIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s19.BridgeNASDeliveryIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "NASDeliveryIndication")
}
func ValidateRetrieveUEInformation(v *s28.RetrieveUEInformation, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	report, err := BridgeValidateRetrieveUEInformationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s28.BridgeRetrieveUEInformationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "RetrieveUEInformation")
}
func ValidateMMECPRelocationIndication(v *s19.MMECPRelocationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	report, err := BridgeValidateMMECPRelocationIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s19.BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMECPRelocationIndication")
}
func ValidateHandoverSuccess(v *s18.HandoverSuccess, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverSuccess")
	}
	report, err := BridgeValidateHandoverSuccessBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s18.BridgeHandoverSuccessMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverSuccess")
}
func ValidateENBEarlyStatusTransfer(v *s38.ENBEarlyStatusTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	report, err := BridgeValidateENBEarlyStatusTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s38.BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBEarlyStatusTransfer")
}
func ValidateMMEEarlyStatusTransfer(v *s38.MMEEarlyStatusTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	report, err := BridgeValidateMMEEarlyStatusTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s38.BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEEarlyStatusTransfer")
}
func ValidateS1RemovalRequest(v *s27.S1RemovalRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1RemovalRequest")
	}
	report, err := BridgeValidateS1RemovalRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s27.BridgeS1RemovalRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1RemovalRequest")
}
func ValidateS1RemovalResponse(v *s27.S1RemovalResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1RemovalResponse")
	}
	report, err := BridgeValidateS1RemovalResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s27.BridgeS1RemovalResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1RemovalResponse")
}
func ValidateS1RemovalFailure(v *s27.S1RemovalFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1RemovalFailure")
	}
	report, err := BridgeValidateS1RemovalFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s27.BridgeS1RemovalFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1RemovalFailure")
}
func BridgeWalkValidationActivatedCellsList(v *s14.ActivatedCellsList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationActivatedCellsListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationActivatedCellsListItem(v *s14.ActivatedCellsListItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAdditionalGUTI(v *s18.AdditionalGUTI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGUMMEI(&v.GUMMEI, report, path+".gUMMEI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeAdditionalGUTIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAllocationAndRetentionPriority(v *s14.AllocationAndRetentionPriority, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeAllocationAndRetentionPriorityExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAreaScopeOfMDT(v *s33.AreaScopeOfMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.AreaScopeOfMDTChoiceCellBased && v.CellBased != nil {
		BridgeWalkValidationCellBasedMDT(v.CellBased, report, path+".cellBased", false)
	}
	if v.Choice == s00.AreaScopeOfMDTChoiceTABased && v.TABased != nil {
		BridgeWalkValidationTABasedMDT(v.TABased, report, path+".tABased", false)
	}
	if v.Choice == s00.AreaScopeOfMDTChoiceTAIBased && v.TAIBased != nil {
		BridgeWalkValidationTAIBasedMDT(v.TAIBased, report, path+".tAIBased", false)
	}
}
func BridgeWalkValidationAreaScopeOfQMC(v *s33.AreaScopeOfQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.AreaScopeOfQMCChoiceCellBased && v.CellBased != nil {
		BridgeWalkValidationCellBasedQMC(v.CellBased, report, path+".cellBased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoiceTABased && v.TABased != nil {
		BridgeWalkValidationTABasedQMC(v.TABased, report, path+".tABased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoiceTAIBased && v.TAIBased != nil {
		BridgeWalkValidationTAIBasedQMC(v.TAIBased, report, path+".tAIBased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoicePLMNAreaBased && v.PLMNAreaBased != nil {
		BridgeWalkValidationPLMNAreaBasedQMC(v.PLMNAreaBased, report, path+".pLMNAreaBased", false)
	}
}
func BridgeWalkValidationAssistanceDataForCECapableUEs(v *s17.AssistanceDataForCECapableUEs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(&v.CellIdentifierAndCELevelForCECapableUEs, report, path+".cellIdentifierAndCELevelForCECapableUEs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeInformationForCECapableUEsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceDataForPaging(v *s26.AssistanceDataForPaging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.AssistanceDataForRecommendedCells != nil {
		BridgeWalkValidationAssistanceDataForRecommendedCells(v.AssistanceDataForRecommendedCells, report, path+".assistanceDataForRecommendedCells", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssistanceDataForCECapableUEs != nil {
		BridgeWalkValidationAssistanceDataForCECapableUEs(v.AssistanceDataForCECapableUEs, report, path+".assistanceDataForCECapableUEs", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.PagingAttemptInformation != nil {
		BridgeWalkValidationPagingAttemptInformation(v.PagingAttemptInformation, report, path+".pagingAttemptInformation", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeAssistanceDataForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceDataForRecommendedCells(v *s26.AssistanceDataForRecommendedCells, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedCellsForPaging(&v.RecommendedCellsForPaging, report, path+".recommendedCellsForPaging", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeAssistanceDataForRecommendedCellsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBPLMNs(v *s00.BPLMNs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationBearersSubjectToDLDiscardingItem(v *s15.BearersSubjectToDLDiscardingItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationDLDiscarding(&v.DLDiscarding, report, path+".dL-Discarding", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeBearersSubjectToDLDiscardingItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBearersSubjectToDLDiscardingList(v *s15.BearersSubjectToDLDiscardingList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s15.BearersSubjectToDLDiscardingItemIEs().BearersSubjectToDLDiscardingItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeBearersSubjectToDLDiscardingItemIEValueValidateS1APIEContainer(s15.BearersSubjectToDLDiscardingItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s15.BearersSubjectToDLDiscardingItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(351):
				if value, ok := fields[i].Value.AsBearersSubjectToDLDiscardingItem(); ok {
					BridgeWalkValidationBearersSubjectToDLDiscardingItem(value, report, fmt.Sprintf("%s[%d]{id=351}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationBearersSubjectToEarlyStatusTransferItem(v *s15.BearersSubjectToEarlyStatusTransferItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationDLCOUNTPDCPSNlength(&v.DLCOUNTPDCPSNlength, report, path+".dLCOUNT-PDCP-SNlength", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBearersSubjectToEarlyStatusTransferList(v *s15.BearersSubjectToEarlyStatusTransferList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s15.BearersSubjectToEarlyStatusTransferItemIEs().BearersSubjectToEarlyStatusTransferItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeBearersSubjectToEarlyStatusTransferItemIEValueValidateS1APIEContainer(s15.BearersSubjectToEarlyStatusTransferItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s15.BearersSubjectToEarlyStatusTransferItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(322):
				if value, ok := fields[i].Value.AsBearersSubjectToEarlyStatusTransferItem(); ok {
					BridgeWalkValidationBearersSubjectToEarlyStatusTransferItem(value, report, fmt.Sprintf("%s[%d]{id=322}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationBearersSubjectToStatusTransferItem(v *s21.BearersSubjectToStatusTransferItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCOUNTvalue(&v.ULCOUNTvalue, report, path+".uL-COUNTvalue", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCOUNTvalue(&v.DLCOUNTvalue, report, path+".dL-COUNTvalue", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s14.BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValueExtended().Info()), s00.FieldInfo(s14.BearersSubjectToStatusTransferItemExtIEs().DLCOUNTValueExtended().Info()), s00.FieldInfo(s14.BearersSubjectToStatusTransferItemExtIEs().ReceiveStatusOfULPDCPSDUsExtended().Info()), s00.FieldInfo(s14.BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValuePDCPSNlength18().Info()), s00.FieldInfo(s14.BearersSubjectToStatusTransferItemExtIEs().DLCOUNTValuePDCPSNlength18().Info()), s00.FieldInfo(s14.BearersSubjectToStatusTransferItemExtIEs().ReceiveStatusOfULPDCPSDUsPDCPSNlength18().Info())}
				s26.BridgeMergeNestedValidation(report, s27.BridgeBearersSubjectToStatusTransferItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(179):
					if value, ok := fields[i].ExtensionValue.AsULCOUNTValueExtended(); ok {
						BridgeWalkValidationCOUNTValueExtended(value, report, fmt.Sprintf("%s[%d]{id=179}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(180):
					if value, ok := fields[i].ExtensionValue.AsDLCOUNTValueExtended(); ok {
						BridgeWalkValidationCOUNTValueExtended(value, report, fmt.Sprintf("%s[%d]{id=180}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(217):
					if value, ok := fields[i].ExtensionValue.AsULCOUNTValuePDCPSNlength18(); ok {
						BridgeWalkValidationCOUNTvaluePDCPSNlength18(value, report, fmt.Sprintf("%s[%d]{id=217}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(218):
					if value, ok := fields[i].ExtensionValue.AsDLCOUNTValuePDCPSNlength18(); ok {
						BridgeWalkValidationCOUNTvaluePDCPSNlength18(value, report, fmt.Sprintf("%s[%d]{id=218}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBearersSubjectToStatusTransferList(v *s21.BearersSubjectToStatusTransferList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s21.BearersSubjectToStatusTransferItemIEs().BearersSubjectToStatusTransferItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeBearersSubjectToStatusTransferItemIEValueValidateS1APIEContainer(s21.BearersSubjectToStatusTransferItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s21.BearersSubjectToStatusTransferItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(89):
				if value, ok := fields[i].Value.AsBearersSubjectToStatusTransferItem(); ok {
					BridgeWalkValidationBearersSubjectToStatusTransferItem(value, report, fmt.Sprintf("%s[%d]{id=89}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationBluetoothMeasConfigNameList(v *s00.BluetoothMeasConfigNameList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationBluetoothMeasurementConfiguration(v *s14.BluetoothMeasurementConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.BluetoothMeasConfigNameList != nil {
		BridgeWalkValidationBluetoothMeasConfigNameList(&v.BluetoothMeasConfigNameList, report, path+".bluetoothMeasConfigNameList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeBluetoothMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBroadcastCancelledAreaList(v *s33.BroadcastCancelledAreaList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.BroadcastCancelledAreaListChoiceCellIDCancelled && v.CellIDCancelled != nil {
		BridgeWalkValidationCellIDCancelled(&v.CellIDCancelled, report, path+".cellID-Cancelled", false)
	}
	if v.Choice == s00.BroadcastCancelledAreaListChoiceTAICancelled && v.TAICancelled != nil {
		BridgeWalkValidationTAICancelled(&v.TAICancelled, report, path+".tAI-Cancelled", false)
	}
	if v.Choice == s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled && v.EmergencyAreaIDCancelled != nil {
		BridgeWalkValidationEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, report, path+".emergencyAreaID-Cancelled", false)
	}
}
func BridgeWalkValidationBroadcastCompletedAreaList(v *s32.BroadcastCompletedAreaList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.BroadcastCompletedAreaListChoiceCellIDBroadcast && v.CellIDBroadcast != nil {
		BridgeWalkValidationCellIDBroadcast(&v.CellIDBroadcast, report, path+".cellID-Broadcast", false)
	}
	if v.Choice == s00.BroadcastCompletedAreaListChoiceTAIBroadcast && v.TAIBroadcast != nil {
		BridgeWalkValidationTAIBroadcast(&v.TAIBroadcast, report, path+".tAI-Broadcast", false)
	}
	if v.Choice == s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast && v.EmergencyAreaIDBroadcast != nil {
		BridgeWalkValidationEmergencyAreaIDBroadcast(&v.EmergencyAreaIDBroadcast, report, path+".emergencyAreaID-Broadcast", false)
	}
}
func BridgeWalkValidationCGI(v *s14.CGI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCGIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCNTypeRestrictions(v *s14.CNTypeRestrictions, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCNTypeRestrictionsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCNTypeRestrictionsItem(v *s14.CNTypeRestrictionsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCNTypeRestrictionsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCOUNTValueExtended(v *s14.COUNTValueExtended, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCOUNTValueExtendedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCOUNTvalue(v *s14.COUNTvalue, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCOUNTvalueExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCOUNTvaluePDCPSNlength18(v *s14.COUNTvaluePDCPSNlength18, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCSGIdList(v *s14.CSGIdList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCSGIdListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCSGIdListItem(v *s14.CSGIdListItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCSGIdListItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCSGMembershipInfo(v *s14.CSGMembershipInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCSGMembershipInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCancelledCellinEAI(v *s17.CancelledCellinEAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCancelledCellinEAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCancelledCellinEAIItem(v *s17.CancelledCellinEAIItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCancelledCellinEAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCancelledCellinTAI(v *s17.CancelledCellinTAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCancelledCellinTAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCancelledCellinTAIItem(v *s17.CancelledCellinTAIItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCancelledCellinTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCandidateCellList(v *s18.CandidateCellList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationIRATCellID(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCandidatePCI(v *s14.CandidatePCI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCandidatePCIList(v *s14.CandidatePCIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCandidatePCI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCause(v *s14.Cause, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationCdma2000OneXSRVCCInfo(v *s14.Cdma2000OneXSRVCCInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCdma2000OneXSRVCCInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellActivationRequest(v *s22.CellActivationRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellsToActivateList(&v.CellsToActivateList, report, path+".cellsToActivateList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellActivationResponse(v *s21.CellActivationResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationActivatedCellsList(&v.ActivatedCellsList, report, path+".activatedCellsList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellBasedMDT(v *s22.CellBasedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellIdListforMDT(&v.CellIdListforMDT, report, path+".cellIdListforMDT", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCellBasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellBasedQMC(v *s22.CellBasedQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellIdListforQMC(&v.CellIdListforQMC, report, path+".cellIdListforQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCellBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellIDBroadcast(v *s17.CellIDBroadcast, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCellIDBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIDBroadcastItem(v *s17.CellIDBroadcastItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCellIDBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellIDCancelled(v *s17.CellIDCancelled, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCellIDCancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIDCancelledItem(v *s17.CellIDCancelledItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCellIDCancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellIdListforMDT(v *s17.CellIdListforMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIdListforQMC(v *s17.CellIdListforQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(v *s17.CellIdentifierAndCELevelForCECapableUEs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.GlobalCellID, report, path+".global-Cell-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellLoadReportingResponse(v *s18.CellLoadReportingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.CellLoadReportingResponseChoiceEUTRAN && v.EUTRAN != nil {
		BridgeWalkValidationEUTRANcellLoadReportingResponse(v.EUTRAN, report, path+".eUTRAN", false)
	}
	if v.Choice == s00.CellLoadReportingResponseChoiceEHRPD && v.EHRPD != nil {
		BridgeWalkValidationEHRPDSectorLoadReportingResponse(v.EHRPD, report, path+".eHRPD", false)
	}
}
func BridgeWalkValidationCellStateIndication(v *s24.CellStateIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationNotificationCellList(&v.NotificationCellList, report, path+".notificationCellList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellTrafficTrace(v *s21.CellTrafficTrace, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s18.CellTrafficTraceIEs().MMEUES1APID().Info(), s18.CellTrafficTraceIEs().ENBUES1APID().Info(), s18.CellTrafficTraceIEs().EUTRANTraceID().Info(), s18.CellTrafficTraceIEs().EUTRANCGI().Info(), s18.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().Info(), s18.CellTrafficTraceIEs().PrivacyIndicator().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeCellTrafficTraceIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellType(v *s14.CellType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCellTypeExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellsToActivateList(v *s14.CellsToActivateList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCellsToActivateListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellsToActivateListItem(v *s14.CellsToActivateListItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCompletedCellinEAI(v *s17.CompletedCellinEAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCompletedCellinEAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCompletedCellinEAIItem(v *s17.CompletedCellinEAIItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCompletedCellinEAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCompletedCellinTAI(v *s17.CompletedCellinTAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCompletedCellinTAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCompletedCellinTAIItem(v *s17.CompletedCellinTAIItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCompletedCellinTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationConnectedengNBItem(v *s31.ConnectedengNBItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSupportedTAs(&v.SupportedTAs, report, path+".supportedTAs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeConnectedengNBItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationConnectedengNBList(v *s31.ConnectedengNBList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationConnectedengNBItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationConnectionEstablishmentIndication(v *s31.ConnectionEstablishmentIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s31.ConnectionEstablishmentIndicationIEs().MMEUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().ENBUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapability().Info(), s31.ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Info(), s31.ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().EndIndication().Info(), s31.ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Info(), s31.ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Info(), s31.ConnectionEstablishmentIndicationIEs().CoarseUELocation().Info()}
			s26.BridgeMergeNestedValidation(report, s31.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(253):
				if value, ok := fields[i].Value.AsDLCPSecurityInformation(); ok {
					BridgeWalkValidationDLCPSecurityInformation(value, report, fmt.Sprintf("%s[%d]{id=253}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(252):
				if value, ok := fields[i].Value.AsUELevelQoSParameters(); ok {
					BridgeWalkValidationERABLevelQoSParameters(value, report, fmt.Sprintf("%s[%d]{id=252}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationContextatSource(v *s19.ContextatSource, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalRANNODEID(&v.SourceNGRANNodeID, report, path+".sourceNG-RAN-node-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeContextatSourceExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCriticalityDiagnostics(v *s22.CriticalityDiagnostics, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEsCriticalityDiagnostics != nil {
		BridgeWalkValidationCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, report, path+".iEsCriticalityDiagnostics", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCriticalityDiagnosticsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCriticalityDiagnosticsIEItem(v *s14.CriticalityDiagnosticsIEItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeCriticalityDiagnosticsIEItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCriticalityDiagnosticsIEList(v *s14.CriticalityDiagnosticsIEList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCriticalityDiagnosticsIEItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationDAPSRequestInfo(v *s14.DAPSRequestInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeDAPSRequestInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDAPSResponseInfo(v *s14.DAPSResponseInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeDAPSResponseInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDAPSResponseInfoItem(v *s14.DAPSResponseInfoItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationDAPSResponseInfo(&v.DAPSResponseInfo, report, path+".dAPSResponseInfo", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeDAPSResponseInfoItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDAPSResponseInfoList(v *s15.DAPSResponseInfoList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s15.DAPSResponseInfoListIEs().DAPSResponseInfoItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeDAPSResponseInfoListIEValueValidateS1APIEContainer(s15.DAPSResponseInfoListIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s15.DAPSResponseInfoListIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(319):
				if value, ok := fields[i].Value.AsDAPSResponseInfoItem(); ok {
					BridgeWalkValidationDAPSResponseInfoItem(value, report, fmt.Sprintf("%s[%d]{id=319}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationDLCOUNTPDCPSNlength(v *s15.DLCOUNTPDCPSNlength, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12 && v.DLCOUNTValuePDCPSNlength12 != nil {
		BridgeWalkValidationCOUNTvalue(v.DLCOUNTValuePDCPSNlength12, report, path+".dLCOUNTValuePDCP-SNlength12", false)
	}
	if v.Choice == s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15 && v.DLCOUNTValuePDCPSNlength15 != nil {
		BridgeWalkValidationCOUNTValueExtended(v.DLCOUNTValuePDCPSNlength15, report, path+".dLCOUNTValuePDCP-SNlength15", false)
	}
	if v.Choice == s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18 && v.DLCOUNTValuePDCPSNlength18 != nil {
		BridgeWalkValidationCOUNTvaluePDCPSNlength18(v.DLCOUNTValuePDCPSNlength18, report, path+".dLCOUNTValuePDCP-SNlength18", false)
	}
}
func BridgeWalkValidationDLCPSecurityInformation(v *s15.DLCPSecurityInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeDLCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDLDiscarding(v *s15.DLDiscarding, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12 && v.DiscardDLCOUNTValuePDCPSNlength12 != nil {
		BridgeWalkValidationCOUNTvalue(v.DiscardDLCOUNTValuePDCPSNlength12, report, path+".discardDLCOUNTValuePDCP-SNlength12", false)
	}
	if v.Choice == s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15 && v.DiscardDLCOUNTValuePDCPSNlength15 != nil {
		BridgeWalkValidationCOUNTValueExtended(v.DiscardDLCOUNTValuePDCPSNlength15, report, path+".discardDLCOUNTValuePDCP-SNlength15", false)
	}
	if v.Choice == s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18 && v.DiscardDLCOUNTValuePDCPSNlength18 != nil {
		BridgeWalkValidationCOUNTvaluePDCPSNlength18(v.DiscardDLCOUNTValuePDCPSNlength18, report, path+".discardDLCOUNTValuePDCP-SNlength18", false)
	}
}
func BridgeWalkValidationDeactivateTrace(v *s15.DeactivateTrace, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s08.DeactivateTraceIEs().MMEUES1APID().Info(), s08.DeactivateTraceIEs().ENBUES1APID().Info(), s08.DeactivateTraceIEs().EUTRANTraceID().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeDeactivateTraceIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDownlinkNASTransport(v *s43.DownlinkNASTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.DownlinkNASTransportIEs().MMEUES1APID().Info(), s43.DownlinkNASTransportIEs().ENBUES1APID().Info(), s43.DownlinkNASTransportIEs().NASPDU().Info(), s43.DownlinkNASTransportIEs().HandoverRestrictionList().Info(), s43.DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Info(), s43.DownlinkNASTransportIEs().SRVCCOperationPossible().Info(), s43.DownlinkNASTransportIEs().UERadioCapability().Info(), s43.DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Info(), s43.DownlinkNASTransportIEs().EnhancedCoverageRestricted().Info(), s43.DownlinkNASTransportIEs().NRUESecurityCapabilities().Info(), s43.DownlinkNASTransportIEs().CEModeBRestricted().Info(), s43.DownlinkNASTransportIEs().UECapabilityInfoRequest().Info(), s43.DownlinkNASTransportIEs().EndIndication().Info(), s43.DownlinkNASTransportIEs().PendingDataIndication().Info(), s43.DownlinkNASTransportIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s43.DownlinkNASTransportIEs().AdditionalRRMPriorityIndex().Info(), s43.DownlinkNASTransportIEs().UERadioCapabilityID().Info(), s43.DownlinkNASTransportIEs().MaskedIMEISV().Info(), s43.DownlinkNASTransportIEs().CoarseUELocation().Info()}
			s26.BridgeMergeNestedValidation(report, s43.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDownlinkNonUEAssociatedLPPaTransport(v *s15.DownlinkNonUEAssociatedLPPaTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s08.DownlinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s08.DownlinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDownlinkS1cdma2000tunnelling(v *s41.DownlinkS1cdma2000tunnelling, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s40.DownlinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s40.DownlinkS1cdma2000tunnellingIEs().ERABSubjecttoDataForwardingList().Info(), s40.DownlinkS1cdma2000tunnellingIEs().Cdma2000HOStatus().Info(), s40.DownlinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s40.DownlinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info()}
			s26.BridgeMergeNestedValidation(report, s41.BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(12):
				if value, ok := fields[i].Value.AsERABSubjecttoDataForwardingList(); ok {
					BridgeWalkValidationERABSubjecttoDataForwardingList(value, report, fmt.Sprintf("%s[%d]{id=12}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDownlinkUEAssociatedLPPaTransport(v *s15.DownlinkUEAssociatedLPPaTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s08.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s08.DownlinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s08.DownlinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s08.DownlinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeDownlinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECGIList(v *s17.ECGIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationECGIListForRestart(v *s17.ECGIListForRestart, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationEHRPDCompositeAvailableCapacity(v *s15.EHRPDCompositeAvailableCapacity, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEHRPDMultiSectorLoadReportingResponseItem(v *s15.EHRPDMultiSectorLoadReportingResponseItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationEHRPDSectorLoadReportingResponse(&v.EHRPDSectorLoadReportingResponse, report, path+".eHRPDSectorLoadReportingResponse", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEHRPDSectorLoadReportingResponse(v *s15.EHRPDSectorLoadReportingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEHRPDCompositeAvailableCapacity(&v.DLEHRPDCompositeAvailableCapacity, report, path+".dL-EHRPD-CompositeAvailableCapacity", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationEHRPDCompositeAvailableCapacity(&v.ULEHRPDCompositeAvailableCapacity, report, path+".uL-EHRPD-CompositeAvailableCapacity", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdate(v *s44.ENBConfigurationUpdate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.ENBConfigurationUpdateIEs().ENBname().Info(), s44.ENBConfigurationUpdateIEs().SupportedTAs().Info(), s44.ENBConfigurationUpdateIEs().CSGIdList().Info(), s44.ENBConfigurationUpdateIEs().DefaultPagingDRX().Info(), s44.ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Info(), s44.ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Info(), s44.ENBConfigurationUpdateIEs().ConnectedengNBToRemoveList().Info()}
			s26.BridgeMergeNestedValidation(report, s44.BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(64):
				if value, ok := fields[i].Value.AsSupportedTAs(); ok {
					BridgeWalkValidationSupportedTAs(value, report, fmt.Sprintf("%s[%d]{id=64}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(292):
				if value, ok := fields[i].Value.AsConnectedengNBToAddList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=292}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(293):
				if value, ok := fields[i].Value.AsConnectedengNBToRemoveList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=293}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdateAcknowledge(v *s24.ENBConfigurationUpdateAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.ENBConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeENBConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdateFailure(v *s24.ENBConfigurationUpdateFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.ENBConfigurationUpdateFailureIEs().Cause().Info(), s22.ENBConfigurationUpdateFailureIEs().TimeToWait().Info(), s22.ENBConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeENBConfigurationUpdateFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBDirectInformationTransfer(v *s34.ENBDirectInformationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s34.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Info()}
			s26.BridgeMergeNestedValidation(report, s34.BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(121):
				if value, ok := fields[i].Value.AsInterSystemInformationTransferTypeEDT(); ok {
					BridgeWalkValidationInterSystemInformationTransferType(value, report, fmt.Sprintf("%s[%d]{id=121}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBEarlyStatusTransfer(v *s38.ENBEarlyStatusTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s38.ENBEarlyStatusTransferIEs().MMEUES1APID().Info(), s38.ENBEarlyStatusTransferIEs().ENBUES1APID().Info(), s38.ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
			s26.BridgeMergeNestedValidation(report, s38.BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(321):
				if value, ok := fields[i].Value.AsENBEarlyStatusTransferTransparentContainer(); ok {
					BridgeWalkValidationENBEarlyStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=321}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBEarlyStatusTransferTransparentContainer(v *s38.ENBEarlyStatusTransferTransparentContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, report, path+".bearers-SubjectToEarlyStatusTransferList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s38.ENBEarlyStatusTransferTransparentContainerExtIEs().BearersSubjectToDLDiscardingList().Info())}
				s26.BridgeMergeNestedValidation(report, s38.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(352):
					if value, ok := fields[i].ExtensionValue.AsBearersSubjectToDLDiscardingList(); ok {
						BridgeWalkValidationBearersSubjectToDLDiscardingList(value, report, fmt.Sprintf("%s[%d]{id=352}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBID(v *s15.ENBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationENBIndirectX2TransportLayerAddresses(v *s00.ENBIndirectX2TransportLayerAddresses, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationENBStatusTransfer(v *s24.ENBStatusTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.ENBStatusTransferIEs().MMEUES1APID().Info(), s22.ENBStatusTransferIEs().ENBUES1APID().Info(), s22.ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeENBStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(90):
				if value, ok := fields[i].Value.AsENBStatusTransferTransparentContainer(); ok {
					BridgeWalkValidationENBStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=90}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBStatusTransferTransparentContainer(v *s21.ENBStatusTransferTransparentContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationBearersSubjectToStatusTransferList(&v.BearersSubjectToStatusTransferList, report, path+".bearers-SubjectToStatusTransferList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENBStatusTransferTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBX2ExtTLA(v *s15.ENBX2ExtTLA, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.GTPTLAa != nil {
		BridgeWalkValidationENBX2GTPTLAs(&v.GTPTLAa, report, path+".gTPTLAa", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENBX2ExtTLAExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBX2ExtTLAs(v *s15.ENBX2ExtTLAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationENBX2ExtTLA(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationENBX2GTPTLAs(v *s00.ENBX2GTPTLAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationENBX2TLAs(v *s00.ENBX2TLAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationENDCSONTransferType(v *s32.ENDCSONTransferType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.ENDCSONTransferTypeChoiceRequest && v.Request != nil {
		BridgeWalkValidationENDCTransferTypeRequest(v.Request, report, path+".request", false)
	}
	if v.Choice == s00.ENDCSONTransferTypeChoiceReply && v.Reply != nil {
		BridgeWalkValidationENDCTransferTypeReply(v.Reply, report, path+".reply", false)
	}
}
func BridgeWalkValidationENDCSONeNBIdentification(v *s32.ENDCSONeNBIdentification, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalENBID(&v.GlobaleNBID, report, path+".globaleNBID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selectedTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENDCSONeNBIdentificationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCSONengNBIdentification(v *s32.ENDCSONengNBIdentification, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalEnGNBID(&v.GlobalengNBID, report, path+".globalengNBID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selectedTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENDCSONengNBIdentificationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCTransferTypeReply(v *s32.ENDCTransferTypeReply, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationENDCSONengNBIdentification(&v.SourceengNB, report, path+".sourceengNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENDCSONeNBIdentification(&v.TargeteNB, report, path+".targeteNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENDCTransferTypeReplyExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCTransferTypeRequest(v *s32.ENDCTransferTypeRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationENDCSONeNBIdentification(&v.SourceeNB, report, path+".sourceeNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENDCSONengNBIdentification(&v.TargetengNB, report, path+".targetengNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.TargeteNB != nil {
		BridgeWalkValidationENDCSONeNBIdentification(v.TargeteNB, report, path+".targeteNB", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssociatedTAI != nil {
		BridgeWalkValidationTAI(v.AssociatedTAI, report, path+".associatedTAI", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.Broadcast5GSTAI != nil {
		BridgeWalkValidationFiveGSTAI(v.Broadcast5GSTAI, report, path+".broadcast5GSTAI", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENDCTransferTypeRequestExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEPLMNs(v *s00.EPLMNs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationERABAdmittedItem(v *s15.ERABAdmittedItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABAdmittedItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABAdmittedList(v *s15.ERABAdmittedList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s15.ERABAdmittedItemIEs().ERABAdmittedItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABAdmittedItemIEValueValidateS1APIEContainer(s15.ERABAdmittedItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s15.ERABAdmittedItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(20):
				if value, ok := fields[i].Value.AsERABAdmittedItem(); ok {
					BridgeWalkValidationERABAdmittedItem(value, report, fmt.Sprintf("%s[%d]{id=20}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABDataForwardingItem(v *s15.ERABDataForwardingItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABDataForwardingItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABFailedToResumeItemResumeReq(v *s15.ERABFailedToResumeItemResumeReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABFailedToResumeItemResumeReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABFailedToResumeItemResumeRes(v *s16.ERABFailedToResumeItemResumeRes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABFailedToResumeItemResumeResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABFailedToResumeListResumeReq(v *s16.ERABFailedToResumeListResumeReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABFailedToResumeItemResumeReqIEs().ERABFailedToResumeItemResumeReq().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABFailedToResumeItemResumeReqIEValueValidateS1APIEContainer(s15.ERABFailedToResumeItemResumeReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s15.ERABFailedToResumeItemResumeReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(236):
				if value, ok := fields[i].Value.AsERABFailedToResumeItemResumeReq(); ok {
					BridgeWalkValidationERABFailedToResumeItemResumeReq(value, report, fmt.Sprintf("%s[%d]{id=236}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABFailedToResumeListResumeRes(v *s16.ERABFailedToResumeListResumeRes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABFailedToResumeItemResumeResIEs().ERABFailedToResumeItemResumeRes().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABFailedToResumeItemResumeResIEValueValidateS1APIEContainer(s16.ERABFailedToResumeItemResumeResIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABFailedToResumeItemResumeResIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(238):
				if value, ok := fields[i].Value.AsERABFailedToResumeItemResumeRes(); ok {
					BridgeWalkValidationERABFailedToResumeItemResumeRes(value, report, fmt.Sprintf("%s[%d]{id=238}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABFailedToSetupItemHOReqAck(v *s16.ERABFailedToSetupItemHOReqAck, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABFailedToSetupItemHOReqAckExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABFailedtoSetupListHOReqAck(v *s16.ERABFailedtoSetupListHOReqAck, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABFailedtoSetupItemHOReqAckIEs().ERABFailedtoSetupItemHOReqAck().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABFailedtoSetupItemHOReqAckIEValueValidateS1APIEContainer(s16.ERABFailedtoSetupItemHOReqAckIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABFailedtoSetupItemHOReqAckIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsERABFailedtoSetupItemHOReqAck(); ok {
					BridgeWalkValidationERABFailedToSetupItemHOReqAck(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABInformationList(v *s29.ERABInformationList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s29.ERABInformationListIEs().ERABInformationListItem().Info()}
		s26.BridgeMergeNestedValidation(report, s29.BridgeERABInformationListIEValueValidateS1APIEContainer(s29.ERABInformationListIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s29.ERABInformationListIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(78):
				if value, ok := fields[i].Value.AsERABInformationListItem(); ok {
					BridgeWalkValidationERABInformationListItem(value, report, fmt.Sprintf("%s[%d]{id=78}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABInformationListItem(v *s29.ERABInformationListItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABInformationListItemExtIEs().DAPSRequestInfo().Info()), s00.FieldInfo(s29.ERABInformationListItemExtIEs().SourceTransportLayerAddress().Info()), s00.FieldInfo(s29.ERABInformationListItemExtIEs().SecurityIndication().Info()), s00.FieldInfo(s29.ERABInformationListItemExtIEs().SourceNodeTransportLayerAddress().Info())}
				s26.BridgeMergeNestedValidation(report, s29.BridgeERABInformationListItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(317):
					if value, ok := fields[i].ExtensionValue.AsDAPSRequestInfo(); ok {
						BridgeWalkValidationDAPSRequestInfo(value, report, fmt.Sprintf("%s[%d]{id=317}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABItem(v *s16.ERABItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABLevelQoSParameters(v *s18.ERABLevelQoSParameters, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationAllocationAndRetentionPriority(&v.AllocationRetentionPriority, report, path+".allocationRetentionPriority", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.GbrQosInformation != nil {
		BridgeWalkValidationGBRQosInformation(v.GbrQosInformation, report, path+".gbrQosInformation", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s08.ERABQoSParametersExtIEs().DownlinkPacketLossRate().Info()), s00.FieldInfo(s08.ERABQoSParametersExtIEs().UplinkPacketLossRate().Info())}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABQoSParametersExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABList(v *s16.ERABList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABItemIEs().ERABItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABItemIEValueValidateS1APIEContainer(s16.ERABItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(35):
				if value, ok := fields[i].Value.AsERABItem(); ok {
					BridgeWalkValidationERABItem(value, report, fmt.Sprintf("%s[%d]{id=35}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABModificationConfirm(v *s40.ERABModificationConfirm, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.ERABModificationConfirmIEs().MMEUES1APID().Info(), s40.ERABModificationConfirmIEs().ENBUES1APID().Info(), s40.ERABModificationConfirmIEs().ERABModifyListBearerModConf().Info(), s40.ERABModificationConfirmIEs().ERABFailedToModifyListBearerModConf().Info(), s40.ERABModificationConfirmIEs().ERABToBeReleasedListBearerModConf().Info(), s40.ERABModificationConfirmIEs().CriticalityDiagnostics().Info(), s40.ERABModificationConfirmIEs().CSGMembershipStatus().Info()}
			s26.BridgeMergeNestedValidation(report, s40.BridgeERABModificationConfirmIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(203):
				if value, ok := fields[i].Value.AsERABModifyListBearerModConf(); ok {
					BridgeWalkValidationERABModifyListBearerModConf(value, report, fmt.Sprintf("%s[%d]{id=203}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(205):
				if value, ok := fields[i].Value.AsERABFailedToModifyListBearerModConf(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=205}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(210):
				if value, ok := fields[i].Value.AsERABToBeReleasedListBearerModConf(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=210}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyItemBearerModConf(v *s16.ERABModifyItemBearerModConf, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABModifyItemBearerModConfExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyItemBearerModRes(v *s16.ERABModifyItemBearerModRes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABModifyItemBearerModResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyListBearerModConf(v *s16.ERABModifyListBearerModConf, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABModifyItemBearerModConfIEs().ERABModifyItemBearerModConf().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABModifyItemBearerModConfIEValueValidateS1APIEContainer(s16.ERABModifyItemBearerModConfIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABModifyItemBearerModConfIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(204):
				if value, ok := fields[i].Value.AsERABModifyItemBearerModConf(); ok {
					BridgeWalkValidationERABModifyItemBearerModConf(value, report, fmt.Sprintf("%s[%d]{id=204}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABModifyListBearerModRes(v *s16.ERABModifyListBearerModRes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABModifyItemBearerModResIEs().ERABModifyItemBearerModRes().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABModifyItemBearerModResIEValueValidateS1APIEContainer(s16.ERABModifyItemBearerModResIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABModifyItemBearerModResIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(37):
				if value, ok := fields[i].Value.AsERABModifyItemBearerModRes(); ok {
					BridgeWalkValidationERABModifyItemBearerModRes(value, report, fmt.Sprintf("%s[%d]{id=37}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABModifyRequest(v *s41.ERABModifyRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s41.ERABModifyRequestIEs().MMEUES1APID().Info(), s41.ERABModifyRequestIEs().ENBUES1APID().Info(), s41.ERABModifyRequestIEs().UEaggregateMaximumBitrate().Info(), s41.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Info(), s41.ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Info()}
			s26.BridgeMergeNestedValidation(report, s41.BridgeERABModifyRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(30):
				if value, ok := fields[i].Value.AsERABToBeModifiedListBearerModReq(); ok {
					BridgeWalkValidationERABToBeModifiedListBearerModReq(value, report, fmt.Sprintf("%s[%d]{id=30}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABNotToBeModifiedItemBearerModInd(v *s16.ERABNotToBeModifiedItemBearerModInd, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABNotToBeModifiedListBearerModInd(v *s16.ERABNotToBeModifiedListBearerModInd, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABNotToBeModifiedItemBearerModIndIEs().ERABNotToBeModifiedItemBearerModInd().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABNotToBeModifiedItemBearerModIndIEValueValidateS1APIEContainer(s16.ERABNotToBeModifiedItemBearerModIndIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABNotToBeModifiedItemBearerModIndIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(202):
				if value, ok := fields[i].Value.AsERABNotToBeModifiedItemBearerModInd(); ok {
					BridgeWalkValidationERABNotToBeModifiedItemBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=202}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABReleaseCommand(v *s40.ERABReleaseCommand, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.ERABReleaseCommandIEs().MMEUES1APID().Info(), s40.ERABReleaseCommandIEs().ENBUES1APID().Info(), s40.ERABReleaseCommandIEs().UEaggregateMaximumBitrate().Info(), s40.ERABReleaseCommandIEs().ERABToBeReleasedList().Info(), s40.ERABReleaseCommandIEs().NASPDU().Info()}
			s26.BridgeMergeNestedValidation(report, s40.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(33):
				if value, ok := fields[i].Value.AsERABToBeReleasedList(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=33}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseItemBearerRelComp(v *s16.ERABReleaseItemBearerRelComp, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABReleaseItemBearerRelCompExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseListBearerRelComp(v *s16.ERABReleaseListBearerRelComp, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s16.ERABReleaseItemBearerRelCompIEs().ERABReleaseItemBearerRelComp().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABReleaseItemBearerRelCompIEValueValidateS1APIEContainer(s16.ERABReleaseItemBearerRelCompIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABReleaseItemBearerRelCompIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(15):
				if value, ok := fields[i].Value.AsERABReleaseItemBearerRelComp(); ok {
					BridgeWalkValidationERABReleaseItemBearerRelComp(value, report, fmt.Sprintf("%s[%d]{id=15}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSecurityResultItem(v *s30.ERABSecurityResultItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSecurityResult(&v.SecurityResult, report, path+".securityResult", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABSecurityResultItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSecurityResultList(v *s30.ERABSecurityResultList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABSecurityResultListIEs().ERABSecurityResultItem().Info()}
		s26.BridgeMergeNestedValidation(report, s30.BridgeERABSecurityResultListIEValueValidateS1APIEContainer(s30.ERABSecurityResultListIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABSecurityResultListIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(334):
				if value, ok := fields[i].Value.AsERABSecurityResultItem(); ok {
					BridgeWalkValidationERABSecurityResultItem(value, report, fmt.Sprintf("%s[%d]{id=334}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSetupItemBearerSURes(v *s16.ERABSetupItemBearerSURes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABSetupItemBearerSUResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSetupItemCtxtSURes(v *s17.ERABSetupItemCtxtSURes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABSetupItemCtxtSUResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSetupListBearerSURes(v *s17.ERABSetupListBearerSURes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s17.ERABSetupItemBearerSUResIEs().ERABSetupItemBearerSURes().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABSetupItemBearerSUResIEValueValidateS1APIEContainer(s16.ERABSetupItemBearerSUResIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s16.ERABSetupItemBearerSUResIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(39):
				if value, ok := fields[i].Value.AsERABSetupItemBearerSURes(); ok {
					BridgeWalkValidationERABSetupItemBearerSURes(value, report, fmt.Sprintf("%s[%d]{id=39}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSetupListCtxtSURes(v *s17.ERABSetupListCtxtSURes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s17.ERABSetupItemCtxtSUResIEs().ERABSetupItemCtxtSURes().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABSetupItemCtxtSUResIEValueValidateS1APIEContainer(s17.ERABSetupItemCtxtSUResIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s17.ERABSetupItemCtxtSUResIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(50):
				if value, ok := fields[i].Value.AsERABSetupItemCtxtSURes(); ok {
					BridgeWalkValidationERABSetupItemCtxtSURes(value, report, fmt.Sprintf("%s[%d]{id=50}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSetupRequest(v *s41.ERABSetupRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s41.ERABSetupRequestIEs().MMEUES1APID().Info(), s41.ERABSetupRequestIEs().ENBUES1APID().Info(), s41.ERABSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s41.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Info()}
			s26.BridgeMergeNestedValidation(report, s41.BridgeERABSetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(16):
				if value, ok := fields[i].Value.AsERABToBeSetupListBearerSUReq(); ok {
					BridgeWalkValidationERABToBeSetupListBearerSUReq(value, report, fmt.Sprintf("%s[%d]{id=16}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSubjecttoDataForwardingList(v *s17.ERABSubjecttoDataForwardingList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s15.ERABDataForwardingItemIEs().ERABDataForwardingItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABDataForwardingItemIEValueValidateS1APIEContainer(s15.ERABDataForwardingItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s15.ERABDataForwardingItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(14):
				if value, ok := fields[i].Value.AsERABDataForwardingItem(); ok {
					BridgeWalkValidationERABDataForwardingItem(value, report, fmt.Sprintf("%s[%d]{id=14}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeModifiedItemBearerModInd(v *s17.ERABToBeModifiedItemBearerModInd, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeModifiedItemBearerModIndExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeModifiedItemBearerModReq(v *s25.ERABToBeModifiedItemBearerModReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationERABLevelQoSParameters(&v.ERABLevelQoSParameters, report, path+".e-RABLevelQoSParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s21.ERABToBeModifyItemBearerModReqExtIEs().TransportInformation().Info())}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeModifyItemBearerModReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(185):
					if value, ok := fields[i].ExtensionValue.AsTransportInformation(); ok {
						BridgeWalkValidationTransportInformation(value, report, fmt.Sprintf("%s[%d]{id=185}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeModifiedListBearerModInd(v *s17.ERABToBeModifiedListBearerModInd, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s17.ERABToBeModifiedItemBearerModIndIEs().ERABToBeModifiedItemBearerModInd().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeModifiedItemBearerModIndIEValueValidateS1APIEContainer(s17.ERABToBeModifiedItemBearerModIndIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s17.ERABToBeModifiedItemBearerModIndIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(200):
				if value, ok := fields[i].Value.AsERABToBeModifiedItemBearerModInd(); ok {
					BridgeWalkValidationERABToBeModifiedItemBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=200}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeModifiedListBearerModReq(v *s25.ERABToBeModifiedListBearerModReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s25.ERABToBeModifiedItemBearerModReqIEs().ERABToBeModifiedItemBearerModReq().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeModifiedItemBearerModReqIEValueValidateS1APIEContainer(s25.ERABToBeModifiedItemBearerModReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s25.ERABToBeModifiedItemBearerModReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(36):
				if value, ok := fields[i].Value.AsERABToBeModifiedItemBearerModReq(); ok {
					BridgeWalkValidationERABToBeModifiedItemBearerModReq(value, report, fmt.Sprintf("%s[%d]{id=36}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupItemBearerSUReq(v *s29.ERABToBeSetupItemBearerSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQoSParameters, report, path+".e-RABlevelQoSParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSetupItemBearerSUReqExtIEs().CorrelationID().Info()), s00.FieldInfo(s29.ERABToBeSetupItemBearerSUReqExtIEs().SIPTOCorrelationID().Info()), s00.FieldInfo(s29.ERABToBeSetupItemBearerSUReqExtIEs().BearerType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemBearerSUReqExtIEs().EthernetType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemBearerSUReqExtIEs().SecurityIndication().Info())}
				s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemBearerSUReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupItemCtxtSUReq(v *s30.ERABToBeSetupItemCtxtSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQoSParameters, report, path+".e-RABlevelQoSParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().CorrelationID().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().SIPTOCorrelationID().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().BearerType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().EthernetType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().SecurityIndication().Info())}
				s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupItemHOReq(v *s30.ERABToBeSetupItemHOReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQosParameters, report, path+".e-RABlevelQosParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().DataForwardingNotPossible().Info()), s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().BearerType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().EthernetType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().SecurityIndication().Info())}
				s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemHOReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupListBearerSUReq(v *s30.ERABToBeSetupListBearerSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABToBeSetupItemBearerSUReqIEs().ERABToBeSetupItemBearerSUReq().Info()}
		s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemBearerSUReqIEValueValidateS1APIEContainer(s30.ERABToBeSetupItemBearerSUReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABToBeSetupItemBearerSUReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsERABToBeSetupItemBearerSUReq(); ok {
					BridgeWalkValidationERABToBeSetupItemBearerSUReq(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupListCtxtSUReq(v *s30.ERABToBeSetupListCtxtSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABToBeSetupItemCtxtSUReqIEs().ERABToBeSetupItemCtxtSUReq().Info()}
		s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemCtxtSUReqIEValueValidateS1APIEContainer(s30.ERABToBeSetupItemCtxtSUReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABToBeSetupItemCtxtSUReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(52):
				if value, ok := fields[i].Value.AsERABToBeSetupItemCtxtSUReq(); ok {
					BridgeWalkValidationERABToBeSetupItemCtxtSUReq(value, report, fmt.Sprintf("%s[%d]{id=52}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupListHOReq(v *s30.ERABToBeSetupListHOReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABToBeSetupItemHOReqIEs().ERABToBeSetupItemHOReq().Info()}
		s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemHOReqIEValueValidateS1APIEContainer(s30.ERABToBeSetupItemHOReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABToBeSetupItemHOReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(27):
				if value, ok := fields[i].Value.AsERABToBeSetupItemHOReq(); ok {
					BridgeWalkValidationERABToBeSetupItemHOReq(value, report, fmt.Sprintf("%s[%d]{id=27}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSwitchedDLItem(v *s30.ERABToBeSwitchedDLItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSwitchedDLItemExtIEs().SecurityIndication().Info())}
				s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSwitchedDLItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSwitchedDLList(v *s30.ERABToBeSwitchedDLList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABToBeSwitchedDLItemIEs().ERABToBeSwitchedDLItem().Info()}
		s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSwitchedDLItemIEValueValidateS1APIEContainer(s30.ERABToBeSwitchedDLItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABToBeSwitchedDLItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(23):
				if value, ok := fields[i].Value.AsERABToBeSwitchedDLItem(); ok {
					BridgeWalkValidationERABToBeSwitchedDLItem(value, report, fmt.Sprintf("%s[%d]{id=23}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSwitchedULItem(v *s17.ERABToBeSwitchedULItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeSwitchedULItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSwitchedULList(v *s17.ERABToBeSwitchedULList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s17.ERABToBeSwitchedULItemIEs().ERABToBeSwitchedULItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeSwitchedULItemIEValueValidateS1APIEContainer(s17.ERABToBeSwitchedULItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s17.ERABToBeSwitchedULItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(94):
				if value, ok := fields[i].Value.AsERABToBeSwitchedULItem(); ok {
					BridgeWalkValidationERABToBeSwitchedULItem(value, report, fmt.Sprintf("%s[%d]{id=94}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeUpdatedItem(v *s29.ERABToBeUpdatedItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.SecurityIndication != nil {
		BridgeWalkValidationSecurityIndication(v.SecurityIndication, report, path+".securityIndication", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABToBeUpdatedItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeUpdatedList(v *s29.ERABToBeUpdatedList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s29.ERABToBeUpdatedItemIEs().ERABToBeUpdatedItem().Info()}
		s26.BridgeMergeNestedValidation(report, s30.BridgeERABToBeUpdatedItemIEValueValidateS1APIEContainer(s29.ERABToBeUpdatedItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s29.ERABToBeUpdatedItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(342):
				if value, ok := fields[i].Value.AsERABToBeUpdatedItem(); ok {
					BridgeWalkValidationERABToBeUpdatedItem(value, report, fmt.Sprintf("%s[%d]{id=342}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABUsageReportItem(v *s17.ERABUsageReportItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeERABUsageReportItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABUsageReportList(v *s17.ERABUsageReportList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s17.ERABUsageReportItemIEs().ERABUsageReportItem().Info()}
		s26.BridgeMergeNestedValidation(report, s27.BridgeERABUsageReportItemIEValueValidateS1APIEContainer(s17.ERABUsageReportItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s17.ERABUsageReportItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(267):
				if value, ok := fields[i].Value.AsERABUsageReportItem(); ok {
					BridgeWalkValidationERABUsageReportItem(value, report, fmt.Sprintf("%s[%d]{id=267}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationEUTRANCGI(v *s17.EUTRANCGI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeEUTRANCGIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEUTRANResponse(v *s18.EUTRANResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationEUTRANcellLoadReportingResponse(&v.EUTRANcellLoadReportingResponse, report, path+".eUTRANcellLoadReportingResponse", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEUTRANcellLoadReportingResponse(v *s18.EUTRANcellLoadReportingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEmergencyAreaIDBroadcast(v *s22.EmergencyAreaIDBroadcast, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEmergencyAreaIDBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationEmergencyAreaIDBroadcastItem(v *s22.EmergencyAreaIDBroadcastItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCompletedCellinEAI(&v.CompletedCellinEAI, report, path+".completedCellinEAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeEmergencyAreaIDBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEmergencyAreaIDCancelled(v *s22.EmergencyAreaIDCancelled, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEmergencyAreaIDCancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationEmergencyAreaIDCancelledItem(v *s22.EmergencyAreaIDCancelledItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCancelledCellinEAI(&v.CancelledCellinEAI, report, path+".cancelledCellinEAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeEmergencyAreaIDCancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEmergencyAreaIDList(v *s00.EmergencyAreaIDList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationEmergencyAreaIDListForRestart(v *s00.EmergencyAreaIDListForRestart, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationErrorIndication(v *s28.ErrorIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s28.ErrorIndicationIEs().MMEUES1APID().Info(), s28.ErrorIndicationIEs().ENBUES1APID().Info(), s28.ErrorIndicationIEs().Cause().Info(), s28.ErrorIndicationIEs().CriticalityDiagnostics().Info(), s28.ErrorIndicationIEs().STMSI().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeErrorIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEventL1LoggedMDTConfig(v *s19.EventL1LoggedMDTConfig, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMeasurementThresholdL1LoggedMDT(&v.L1Threshold, report, path+".l1Threshold", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeEventL1LoggedMDTConfigExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEventTrigger(v *s19.EventTrigger, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.EventTriggerChoiceEventL1LoggedMDTConfig && v.EventL1LoggedMDTConfig != nil {
		BridgeWalkValidationEventL1LoggedMDTConfig(v.EventL1LoggedMDTConfig, report, path+".eventL1LoggedMDTConfig", false)
	}
}
func BridgeWalkValidationEventTriggeredCellLoadReportingRequest(v *s18.EventTriggeredCellLoadReportingRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEventTriggeredCellLoadReportingResponse(v *s18.EventTriggeredCellLoadReportingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellLoadReportingResponse(&v.CellLoadReportingResponse, report, path+".cellLoadReportingResponse", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationExpectedUEActivityBehaviour(v *s18.ExpectedUEActivityBehaviour, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeExpectedUEActivityBehaviourExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationExpectedUEBehaviour(v *s18.ExpectedUEBehaviour, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.ExpectedActivity != nil {
		BridgeWalkValidationExpectedUEActivityBehaviour(v.ExpectedActivity, report, path+".expectedActivity", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeExpectedUEBehaviourExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationFailureEventReport(v *s21.FailureEventReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN && v.TooEarlyInterRATHOReportFromEUTRAN != nil {
		BridgeWalkValidationTooEarlyInterRATHOReportReportFromEUTRAN(v.TooEarlyInterRATHOReportFromEUTRAN, report, path+".tooEarlyInterRATHOReportFromEUTRAN", false)
	}
}
func BridgeWalkValidationFiveGSTAI(v *s18.FiveGSTAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeFiveGSTAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationForbiddenLACs(v *s00.ForbiddenLACs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationForbiddenLAs(v *s18.ForbiddenLAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationForbiddenLAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationForbiddenLAsItem(v *s18.ForbiddenLAsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationForbiddenLACs(&v.ForbiddenLACs, report, path+".forbiddenLACs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeForbiddenLAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationForbiddenTACs(v *s00.ForbiddenTACs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationForbiddenTAs(v *s18.ForbiddenTAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationForbiddenTAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationForbiddenTAsItem(v *s18.ForbiddenTAsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationForbiddenTACs(&v.ForbiddenTACs, report, path+".forbiddenTACs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeForbiddenTAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGBRQosInformation(v *s18.GBRQosInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s09.GBRQosInformationExtIEs().ExtendedERABMaximumBitrateDL().Info()), s00.FieldInfo(s09.GBRQosInformationExtIEs().ExtendedERABMaximumBitrateUL().Info()), s00.FieldInfo(s09.GBRQosInformationExtIEs().ExtendedERABGuaranteedBitrateDL().Info()), s00.FieldInfo(s09.GBRQosInformationExtIEs().ExtendedERABGuaranteedBitrateUL().Info())}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGBRQosInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGERANCellID(v *s18.GERANCellID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationLAI(&v.LAI, report, path+".lAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGERANCellIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGNB(v *s18.GNB, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalGNBID(&v.GlobalGNBID, report, path+".global-gNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGNBExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGNBIdentity(v *s18.GNBIdentity, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationGUMMEI(v *s18.GUMMEI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGUMMEIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGUMMEIList(v *s18.GUMMEIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationGUMMEI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationGlobalENBID(v *s18.GlobalENBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENBID(&v.ENBID, report, path+".eNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGlobalENBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGlobalEnGNBID(v *s18.GlobalEnGNBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGlobalEnGNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGlobalGNBID(v *s18.GlobalGNBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationGNBIdentity(&v.GNBID, report, path+".gNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeGlobalGNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationGlobalRANNODEID(v *s19.GlobalRANNODEID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.GlobalRANNODEIDChoiceGNB && v.GNB != nil {
		BridgeWalkValidationGNB(v.GNB, report, path+".gNB", false)
	}
	if v.Choice == s00.GlobalRANNODEIDChoiceNgENB && v.NgENB != nil {
		BridgeWalkValidationNGENB(v.NgENB, report, path+".ng-eNB", false)
	}
}
func BridgeWalkValidationHOReport(v *s22.HOReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationIRATCellID(&v.HosourceID, report, path+".hosourceID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationIRATCellID(&v.HoTargetID, report, path+".hoTargetID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCandidateCellList(&v.CandidateCellList, report, path+".candidateCellList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.CandidatePCIList != nil {
		BridgeWalkValidationCandidatePCIList(&v.CandidatePCIList, report, path+".candidatePCIList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverCancel(v *s25.HandoverCancel, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s18.HandoverCancelIEs().MMEUES1APID().Info(), s18.HandoverCancelIEs().ENBUES1APID().Info(), s18.HandoverCancelIEs().Cause().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeHandoverCancelIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverCancelAcknowledge(v *s25.HandoverCancelAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.HandoverCancelAcknowledgeIEs().MMEUES1APID().Info(), s22.HandoverCancelAcknowledgeIEs().ENBUES1APID().Info(), s22.HandoverCancelAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeHandoverCancelAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverCommand(v *s41.HandoverCommand, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s41.HandoverCommandIEs().MMEUES1APID().Info(), s41.HandoverCommandIEs().ENBUES1APID().Info(), s41.HandoverCommandIEs().HandoverType().Info(), s41.HandoverCommandIEs().NASSecurityParametersfromEUTRAN().Info(), s41.HandoverCommandIEs().ERABSubjecttoDataForwardingList().Info(), s41.HandoverCommandIEs().ERABtoReleaseListHOCmd().Info(), s41.HandoverCommandIEs().TargetToSourceTransparentContainer().Info(), s41.HandoverCommandIEs().TargetToSourceTransparentContainerSecondary().Info(), s41.HandoverCommandIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s41.BridgeHandoverCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(12):
				if value, ok := fields[i].Value.AsERABSubjecttoDataForwardingList(); ok {
					BridgeWalkValidationERABSubjecttoDataForwardingList(value, report, fmt.Sprintf("%s[%d]{id=12}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsERABtoReleaseListHOCmd(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverFailure(v *s25.HandoverFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.HandoverFailureIEs().MMEUES1APID().Info(), s22.HandoverFailureIEs().Cause().Info(), s22.HandoverFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeHandoverFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverNotify(v *s36.HandoverNotify, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s35.HandoverNotifyIEs().MMEUES1APID().Info(), s35.HandoverNotifyIEs().ENBUES1APID().Info(), s35.HandoverNotifyIEs().EUTRANCGI().Info(), s35.HandoverNotifyIEs().TAI().Info(), s35.HandoverNotifyIEs().TunnelInformationForBBF().Info(), s35.HandoverNotifyIEs().LHNID().Info(), s35.HandoverNotifyIEs().PSCellInformation().Info(), s35.HandoverNotifyIEs().NotifySourceeNB().Info(), s35.HandoverNotifyIEs().LTENTNTAIInformation().Info()}
			s26.BridgeMergeNestedValidation(report, s36.BridgeHandoverNotifyIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverPreparationFailure(v *s25.HandoverPreparationFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.HandoverPreparationFailureIEs().MMEUES1APID().Info(), s22.HandoverPreparationFailureIEs().ENBUES1APID().Info(), s22.HandoverPreparationFailureIEs().Cause().Info(), s22.HandoverPreparationFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeHandoverPreparationFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRequestAcknowledge(v *s39.HandoverRequestAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s39.HandoverRequestAcknowledgeIEs().MMEUES1APID().Info(), s39.HandoverRequestAcknowledgeIEs().ENBUES1APID().Info(), s39.HandoverRequestAcknowledgeIEs().ERABAdmittedList().Info(), s39.HandoverRequestAcknowledgeIEs().ERABFailedToSetupListHOReqAck().Info(), s39.HandoverRequestAcknowledgeIEs().TargetToSourceTransparentContainer().Info(), s39.HandoverRequestAcknowledgeIEs().CSGId().Info(), s39.HandoverRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s39.HandoverRequestAcknowledgeIEs().CellAccessMode().Info(), s39.HandoverRequestAcknowledgeIEs().CEModeBSupportIndicator().Info()}
			s26.BridgeMergeNestedValidation(report, s39.BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(18):
				if value, ok := fields[i].Value.AsERABAdmittedList(); ok {
					BridgeWalkValidationERABAdmittedList(value, report, fmt.Sprintf("%s[%d]{id=18}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(19):
				if value, ok := fields[i].Value.AsERABFailedToSetupListHOReqAck(); ok {
					BridgeWalkValidationERABFailedtoSetupListHOReqAck(value, report, fmt.Sprintf("%s[%d]{id=19}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRequired(v *s35.HandoverRequired, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s34.HandoverRequiredIEs().MMEUES1APID().Info(), s34.HandoverRequiredIEs().ENBUES1APID().Info(), s34.HandoverRequiredIEs().HandoverType().Info(), s34.HandoverRequiredIEs().Cause().Info(), s34.HandoverRequiredIEs().TargetID().Info(), s34.HandoverRequiredIEs().DirectForwardingPathAvailability().Info(), s34.HandoverRequiredIEs().SRVCCHOIndication().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainer().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainerSecondary().Info(), s34.HandoverRequiredIEs().MSClassmark2().Info(), s34.HandoverRequiredIEs().MSClassmark3().Info(), s34.HandoverRequiredIEs().CSGId().Info(), s34.HandoverRequiredIEs().CellAccessMode().Info(), s34.HandoverRequiredIEs().PSServiceNotAvailable().Info()}
			s26.BridgeMergeNestedValidation(report, s35.BridgeHandoverRequiredIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(4):
				if value, ok := fields[i].Value.AsTargetID(); ok {
					BridgeWalkValidationTargetID(value, report, fmt.Sprintf("%s[%d]{id=4}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRestrictionList(v *s43.HandoverRestrictionList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.EquivalentPLMNs != nil {
		BridgeWalkValidationEPLMNs(&v.EquivalentPLMNs, report, path+".equivalentPLMNs", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ForbiddenTAs != nil {
		BridgeWalkValidationForbiddenTAs(&v.ForbiddenTAs, report, path+".forbiddenTAs", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ForbiddenLAs != nil {
		BridgeWalkValidationForbiddenLAs(&v.ForbiddenLAs, report, path+".forbiddenLAs", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s43.HandoverRestrictionListExtIEs().NRrestrictioninEPSasSecondaryRAT().Info()), s00.FieldInfo(s43.HandoverRestrictionListExtIEs().UnlicensedSpectrumRestriction().Info()), s00.FieldInfo(s43.HandoverRestrictionListExtIEs().CNTypeRestrictions().Info()), s00.FieldInfo(s43.HandoverRestrictionListExtIEs().NRrestrictionin5GS().Info()), s00.FieldInfo(s43.HandoverRestrictionListExtIEs().LastNGRANPLMNIdentity().Info()), s00.FieldInfo(s43.HandoverRestrictionListExtIEs().RATRestrictions().Info())}
				s26.BridgeMergeNestedValidation(report, s43.BridgeHandoverRestrictionListExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(282):
					if value, ok := fields[i].ExtensionValue.AsCNTypeRestrictions(); ok {
						BridgeWalkValidationCNTypeRestrictions(value, report, fmt.Sprintf("%s[%d]{id=282}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(336):
					if value, ok := fields[i].ExtensionValue.AsRATRestrictions(); ok {
						BridgeWalkValidationRATRestrictions(value, report, fmt.Sprintf("%s[%d]{id=336}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverSuccess(v *s18.HandoverSuccess, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s09.HandoverSuccessIEs().MMEUES1APID().Info(), s09.HandoverSuccessIEs().ENBUES1APID().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeHandoverSuccessIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationIEsECGIList(v *s18.IEsECGIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationIRATCellID(v *s18.IRATCellID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(v *s34.InformationOnRecommendedCellsAndENBsForPaging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedCellsForPaging(&v.RecommendedCellsForPaging, report, path+".recommendedCellsForPaging", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationRecommendedENBsForPaging(&v.RecommendENBsForPaging, report, path+".recommendENBsForPaging", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialContextSetupFailure(v *s25.InitialContextSetupFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.InitialContextSetupFailureIEs().MMEUES1APID().Info(), s23.InitialContextSetupFailureIEs().ENBUES1APID().Info(), s23.InitialContextSetupFailureIEs().Cause().Info(), s23.InitialContextSetupFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s27.BridgeInitialContextSetupFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialContextSetupResponse(v *s40.InitialContextSetupResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.InitialContextSetupResponseIEs().MMEUES1APID().Info(), s40.InitialContextSetupResponseIEs().ENBUES1APID().Info(), s40.InitialContextSetupResponseIEs().ERABSetupListCtxtSURes().Info(), s40.InitialContextSetupResponseIEs().ERABFailedToSetupListCtxtSURes().Info(), s40.InitialContextSetupResponseIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s40.BridgeInitialContextSetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(51):
				if value, ok := fields[i].Value.AsERABSetupListCtxtSURes(); ok {
					BridgeWalkValidationERABSetupListCtxtSURes(value, report, fmt.Sprintf("%s[%d]{id=51}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(48):
				if value, ok := fields[i].Value.AsERABFailedToSetupListCtxtSURes(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=48}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialUEMessage(v *s36.InitialUEMessage, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s36.InitialUEMessageIEs().ENBUES1APID().Info(), s36.InitialUEMessageIEs().NASPDU().Info(), s36.InitialUEMessageIEs().TAI().Info(), s36.InitialUEMessageIEs().EUTRANCGI().Info(), s36.InitialUEMessageIEs().RRCEstablishmentCause().Info(), s36.InitialUEMessageIEs().STMSI().Info(), s36.InitialUEMessageIEs().CSGId().Info(), s36.InitialUEMessageIEs().GUMMEIID().Info(), s36.InitialUEMessageIEs().CellAccessMode().Info(), s36.InitialUEMessageIEs().GWTransportLayerAddress().Info(), s36.InitialUEMessageIEs().RelayNodeIndicator().Info(), s36.InitialUEMessageIEs().GUMMEIType().Info(), s36.InitialUEMessageIEs().TunnelInformationForBBF().Info(), s36.InitialUEMessageIEs().SIPTOLGWTransportLayerAddress().Info(), s36.InitialUEMessageIEs().LHNID().Info(), s36.InitialUEMessageIEs().MMEGroupID().Info(), s36.InitialUEMessageIEs().UEUsageType().Info(), s36.InitialUEMessageIEs().CEModeBSupportIndicator().Info(), s36.InitialUEMessageIEs().DCNID().Info(), s36.InitialUEMessageIEs().CoverageLevel().Info(), s36.InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Info(), s36.InitialUEMessageIEs().EDTSession().Info(), s36.InitialUEMessageIEs().IABNodeIndication().Info(), s36.InitialUEMessageIEs().LTENTNTAIInformation().Info(), s36.InitialUEMessageIEs().CoarseUELocationRequested().Info()}
			s26.BridgeMergeNestedValidation(report, s36.BridgeInitialUEMessageIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterSystemInformationTransferType(v *s34.InterSystemInformationTransferType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.InterSystemInformationTransferTypeChoiceRIMTransfer && v.RIMTransfer != nil {
		BridgeWalkValidationRIMTransfer(v.RIMTransfer, report, path+".rIMTransfer", false)
	}
}
func BridgeWalkValidationInterSystemMeasurementItem(v *s18.InterSystemMeasurementItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeInterSystemMeasurementItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterSystemMeasurementList(v *s18.InterSystemMeasurementList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationInterSystemMeasurementItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationInterSystemMeasurementParameters(v *s24.InterSystemMeasurementParameters, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.InterSystemMeasurementList != nil {
		BridgeWalkValidationInterSystemMeasurementList(&v.InterSystemMeasurementList, report, path+".interSystemMeasurementList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeInterSystemMeasurementParametersExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationIntersystemMeasurementConfiguration(v *s24.IntersystemMeasurementConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationInterSystemMeasurementParameters(&v.InterSystemMeasurementParameters, report, path+".interSystemMeasurementParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeIntersystemMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationKillResponse(v *s33.KillResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s33.KillResponseIEs().MessageIdentifier().Info(), s33.KillResponseIEs().SerialNumber().Info(), s33.KillResponseIEs().BroadcastCancelledAreaList().Info(), s33.KillResponseIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s33.BridgeKillResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(141):
				if value, ok := fields[i].Value.AsBroadcastCancelledAreaList(); ok {
					BridgeWalkValidationBroadcastCancelledAreaList(value, report, fmt.Sprintf("%s[%d]{id=141}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLAI(v *s18.LAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeLAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLTENTNTAIInformation(v *s18.LTENTNTAIInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTACListInLTENTN(&v.TACListInLTENTN, report, path+".tACList-In-LTE-NTN", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeLTENTNTAIInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLastVisitedCellItem(v *s42.LastVisitedCellItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.LastVisitedCellItemChoiceEUTRANCell && v.EUTRANCell != nil {
		BridgeWalkValidationLastVisitedEUTRANCellInformation(v.EUTRANCell, report, path+".e-UTRAN-Cell", false)
	}
	if v.Choice == s00.LastVisitedCellItemChoiceGERANCell && v.GERANCell != nil {
		BridgeWalkValidationLastVisitedGERANCellInformation(v.GERANCell, report, path+".gERAN-Cell", false)
	}
}
func BridgeWalkValidationLastVisitedEUTRANCellInformation(v *s42.LastVisitedEUTRANCellInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.GlobalCellID, report, path+".global-Cell-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCellType(&v.CellType, report, path+".cellType", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s42.LastVisitedEUTRANCellInformationExtIEs().TimeUEStayedInCellEnhancedGranularity().Info()), s00.FieldInfo(s42.LastVisitedEUTRANCellInformationExtIEs().HOCause().Info()), s00.FieldInfo(s42.LastVisitedEUTRANCellInformationExtIEs().LastVisitedPSCellList().Info())}
				s26.BridgeMergeNestedValidation(report, s42.BridgeLastVisitedEUTRANCellInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(168):
					if value, ok := fields[i].ExtensionValue.AsHOCause(); ok {
						BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=168}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(329):
					if value, ok := fields[i].ExtensionValue.AsLastVisitedPSCellList(); ok {
						BridgeWalkValidationLastVisitedPSCellList(value, report, fmt.Sprintf("%s[%d]{id=329}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLastVisitedGERANCellInformation(v *s18.LastVisitedGERANCellInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationLastVisitedPSCellInformation(v *s20.LastVisitedPSCellInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.PSCellID != nil {
		BridgeWalkValidationPSCellInformation(v.PSCellID, report, path+".pSCellID", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeLastVisitedPSCellInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLastVisitedPSCellList(v *s20.LastVisitedPSCellList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationLastVisitedPSCellInformation(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationListeningSubframePattern(v *s19.ListeningSubframePattern, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeListeningSubframePatternExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLocationReport(v *s33.LocationReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s32.LocationReportIEs().MMEUES1APID().Info(), s32.LocationReportIEs().ENBUES1APID().Info(), s32.LocationReportIEs().EUTRANCGI().Info(), s32.LocationReportIEs().TAI().Info(), s32.LocationReportIEs().RequestType().Info(), s32.LocationReportIEs().PSCellInformation().Info(), s32.LocationReportIEs().LTENTNTAIInformation().Info()}
			s26.BridgeMergeNestedValidation(report, s33.BridgeLocationReportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLocationReportingControl(v *s26.LocationReportingControl, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s26.LocationReportingControlIEs().MMEUES1APID().Info(), s26.LocationReportingControlIEs().ENBUES1APID().Info(), s26.LocationReportingControlIEs().RequestType().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeLocationReportingControlIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLocationReportingFailureIndication(v *s25.LocationReportingFailureIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s19.LocationReportingFailureIndicationIEs().MMEUES1APID().Info(), s19.LocationReportingFailureIndicationIEs().ENBUES1APID().Info(), s19.LocationReportingFailureIndicationIEs().Cause().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeLocationReportingFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLoggedMBSFNMDT(v *s24.LoggedMBSFNMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.MBSFNResultToLog != nil {
		BridgeWalkValidationMBSFNResultToLog(&v.MBSFNResultToLog, report, path+".mBSFN-ResultToLog", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeLoggedMBSFNMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLoggedMDTTrigger(v *s19.LoggedMDTTrigger, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.LoggedMDTTriggerChoiceEventTrigger && v.EventTrigger != nil {
		BridgeWalkValidationEventTrigger(v.EventTrigger, report, path+".eventTrigger", false)
	}
}
func BridgeWalkValidationM1PeriodicReporting(v *s19.M1PeriodicReporting, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM1PeriodicReportingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationM1ThresholdEventA2(v *s19.M1ThresholdEventA2, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMeasurementThresholdA2(&v.MeasurementThreshold, report, path+".measurementThreshold", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM1ThresholdEventA2ExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationM3Configuration(v *s19.M3Configuration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM3ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationM4Configuration(v *s19.M4Configuration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.M4ConfigurationExtIEs().M4ReportAmount().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM4ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationM5Configuration(v *s19.M5Configuration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.M5ConfigurationExtIEs().M5ReportAmount().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM5ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationM6Configuration(v *s19.M6Configuration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.M6ConfigurationExtIEs().M6ReportAmount().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM6ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationM7Configuration(v *s19.M7Configuration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.M7ConfigurationExtIEs().M7ReportAmount().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeM7ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMBSFNResultToLog(v *s19.MBSFNResultToLog, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationMBSFNResultToLogInfo(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMBSFNResultToLogInfo(v *s19.MBSFNResultToLogInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeMBSFNResultToLogInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTModeExtension(v *s19.MDTModeExtension, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTPLMNList(v *s00.MDTPLMNList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationMMECPRelocationIndication(v *s19.MMECPRelocationIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.MMECPRelocationIndicationIEs().MMEUES1APID().Info(), s10.MMECPRelocationIndicationIEs().ENBUES1APID().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeMMECPRelocationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEConfigurationUpdate(v *s44.MMEConfigurationUpdate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.MMEConfigurationUpdateIEs().MMEname().Info(), s44.MMEConfigurationUpdateIEs().ServedGUMMEIs().Info(), s44.MMEConfigurationUpdateIEs().RelativeMMECapacity().Info(), s44.MMEConfigurationUpdateIEs().ServedDCNs().Info()}
			s26.BridgeMergeNestedValidation(report, s44.BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(105):
				if value, ok := fields[i].Value.AsServedGUMMEIs(); ok {
					BridgeWalkValidationServedGUMMEIs(value, report, fmt.Sprintf("%s[%d]{id=105}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(247):
				if value, ok := fields[i].Value.AsServedDCNs(); ok {
					BridgeWalkValidationServedDCNs(value, report, fmt.Sprintf("%s[%d]{id=247}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEConfigurationUpdateAcknowledge(v *s25.MMEConfigurationUpdateAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.MMEConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeMMEConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEConfigurationUpdateFailure(v *s26.MMEConfigurationUpdateFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.MMEConfigurationUpdateFailureIEs().Cause().Info(), s23.MMEConfigurationUpdateFailureIEs().TimeToWait().Info(), s23.MMEConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeMMEConfigurationUpdateFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEDirectInformationTransfer(v *s34.MMEDirectInformationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s34.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().Info()}
			s26.BridgeMergeNestedValidation(report, s34.BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(122):
				if value, ok := fields[i].Value.AsInterSystemInformationTransferTypeMDT(); ok {
					BridgeWalkValidationInterSystemInformationTransferType(value, report, fmt.Sprintf("%s[%d]{id=122}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEEarlyStatusTransfer(v *s38.MMEEarlyStatusTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s38.MMEEarlyStatusTransferIEs().MMEUES1APID().Info(), s38.MMEEarlyStatusTransferIEs().ENBUES1APID().Info(), s38.MMEEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
			s26.BridgeMergeNestedValidation(report, s38.BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(321):
				if value, ok := fields[i].Value.AsENBEarlyStatusTransferTransparentContainer(); ok {
					BridgeWalkValidationENBEarlyStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=321}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEPagingTarget(v *s32.MMEPagingTarget, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MMEPagingTargetChoiceGlobalENBID && v.GlobalENBID != nil {
		BridgeWalkValidationGlobalENBID(v.GlobalENBID, report, path+".global-ENB-ID", false)
	}
	if v.Choice == s00.MMEPagingTargetChoiceTAI && v.TAI != nil {
		BridgeWalkValidationTAI(v.TAI, report, path+".tAI", false)
	}
}
func BridgeWalkValidationMMEStatusTransfer(v *s26.MMEStatusTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.MMEStatusTransferIEs().MMEUES1APID().Info(), s22.MMEStatusTransferIEs().ENBUES1APID().Info(), s22.MMEStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeMMEStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(90):
				if value, ok := fields[i].Value.AsENBStatusTransferTransparentContainer(); ok {
					BridgeWalkValidationENBStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=90}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMeasurementThresholdA2(v *s19.MeasurementThresholdA2, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationMeasurementThresholdL1LoggedMDT(v *s19.MeasurementThresholdL1LoggedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationMultiCellLoadReportingRequest(v *s24.MultiCellLoadReportingRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRequestedCellList(&v.RequestedCellList, report, path+".requestedCellList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMultiCellLoadReportingResponse(v *s19.MultiCellLoadReportingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationMultiCellLoadReportingResponseItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMultiCellLoadReportingResponseItem(v *s19.MultiCellLoadReportingResponseItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse && v.EUTRANResponse != nil {
		BridgeWalkValidationEUTRANResponse(v.EUTRANResponse, report, path+".eUTRANResponse", false)
	}
	if v.Choice == s00.MultiCellLoadReportingResponseItemChoiceEHRPD && v.EHRPD != nil {
		BridgeWalkValidationEHRPDMultiSectorLoadReportingResponseItem(v.EHRPD, report, path+".eHRPD", false)
	}
}
func BridgeWalkValidationMutingPatternInformation(v *s19.MutingPatternInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeMutingPatternInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNASDeliveryIndication(v *s19.NASDeliveryIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.NASDeliveryIndicationIEs().MMEUES1APID().Info(), s10.NASDeliveryIndicationIEs().ENBUES1APID().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeNASDeliveryIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNASNonDeliveryIndication(v *s26.NASNonDeliveryIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s19.NASNonDeliveryIndicationIEs().MMEUES1APID().Info(), s19.NASNonDeliveryIndicationIEs().ENBUES1APID().Info(), s19.NASNonDeliveryIndicationIEs().NASPDU().Info(), s19.NASNonDeliveryIndicationIEs().Cause().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeNASNonDeliveryIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNBIoTPagingEDRXInformation(v *s19.NBIoTPagingEDRXInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeNBIoTPagingEDRXInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNGENB(v *s19.NGENB, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalENBID(&v.GlobalNgENBID, report, path+".global-ng-eNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeNGENBExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNRCGI(v *s19.NRCGI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeNRCGIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNRUESecurityCapabilities(v *s19.NRUESecurityCapabilities, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeNRUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(v *s20.NRUESidelinkAggregateMaximumBitrate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNRV2XServicesAuthorized(v *s20.NRV2XServicesAuthorized, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeNRV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNotificationCellList(v *s20.NotificationCellList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationNotificationCellListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationNotificationCellListItem(v *s20.NotificationCellListItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOverloadResponse(v *s20.OverloadResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationOverloadStart(v *s42.OverloadStart, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s42.OverloadStartIEs().OverloadResponse().Info(), s42.OverloadStartIEs().GUMMEIList().Info(), s42.OverloadStartIEs().TrafficLoadReductionIndication().Info()}
			s26.BridgeMergeNestedValidation(report, s42.BridgeOverloadStartIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(101):
				if value, ok := fields[i].Value.AsOverloadResponse(); ok {
					BridgeWalkValidationOverloadResponse(value, report, fmt.Sprintf("%s[%d]{id=101}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(154):
				if value, ok := fields[i].Value.AsGUMMEIList(); ok {
					BridgeWalkValidationGUMMEIList(value, report, fmt.Sprintf("%s[%d]{id=154}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOverloadStop(v *s42.OverloadStop, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s42.OverloadStopIEs().GUMMEIList().Info()}
			s26.BridgeMergeNestedValidation(report, s42.BridgeOverloadStopIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(154):
				if value, ok := fields[i].Value.AsGUMMEIList(); ok {
					BridgeWalkValidationGUMMEIList(value, report, fmt.Sprintf("%s[%d]{id=154}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPC5FlowBitRates(v *s20.PC5FlowBitRates, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePC5FlowBitRatesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPC5QoSFlowItem(v *s20.PC5QoSFlowItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.Pc5FlowBitRates != nil {
		BridgeWalkValidationPC5FlowBitRates(v.Pc5FlowBitRates, report, path+".pc5FlowBitRates", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePC5QoSFlowItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPC5QoSFlowList(v *s20.PC5QoSFlowList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationPC5QoSFlowItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPC5QoSParameters(v *s24.PC5QoSParameters, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationPC5QoSFlowList(&v.Pc5QoSFlowList, report, path+".pc5QoSFlowList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePC5QoSParametersExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPLMNAreaBasedQMC(v *s20.PLMNAreaBasedQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationPLMNListforQMC(&v.PlmnListforQMC, report, path+".plmnListforQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePLMNAreaBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPLMNListforQMC(v *s00.PLMNListforQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPSCellInformation(v *s20.PSCellInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationNRCGI(&v.NCGI, report, path+".nCGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePSCellInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPWSFailureIndication(v *s43.PWSFailureIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.PWSFailureIndicationIEs().PWSfailedECGIList().Info(), s43.PWSFailureIndicationIEs().GlobalENBID().Info()}
			s26.BridgeMergeNestedValidation(report, s43.BridgePWSFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(222):
				if value, ok := fields[i].Value.AsPWSfailedECGIList(); ok {
					BridgeWalkValidationPWSfailedECGIList(value, report, fmt.Sprintf("%s[%d]{id=222}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPWSRestartIndication(v *s44.PWSRestartIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.PWSRestartIndicationIEs().ECGIListForRestart().Info(), s44.PWSRestartIndicationIEs().GlobalENBID().Info(), s44.PWSRestartIndicationIEs().TAIListForRestart().Info(), s44.PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Info()}
			s26.BridgeMergeNestedValidation(report, s45.BridgePWSRestartIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(182):
				if value, ok := fields[i].Value.AsECGIListForRestart(); ok {
					BridgeWalkValidationECGIListForRestart(value, report, fmt.Sprintf("%s[%d]{id=182}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(188):
				if value, ok := fields[i].Value.AsTAIListForRestart(); ok {
					BridgeWalkValidationTAIListForRestart(value, report, fmt.Sprintf("%s[%d]{id=188}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(190):
				if value, ok := fields[i].Value.AsEmergencyAreaIDListForRestart(); ok {
					BridgeWalkValidationEmergencyAreaIDListForRestart(value, report, fmt.Sprintf("%s[%d]{id=190}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPWSfailedECGIList(v *s20.PWSfailedECGIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPagingAttemptInformation(v *s20.PagingAttemptInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePagingAttemptInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPagingEDRXInformation(v *s20.PagingEDRXInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgePagingEDRXInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPathSwitchRequestFailure(v *s26.PathSwitchRequestFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.PathSwitchRequestFailureIEs().MMEUES1APID().Info(), s23.PathSwitchRequestFailureIEs().ENBUES1APID().Info(), s23.PathSwitchRequestFailureIEs().Cause().Info(), s23.PathSwitchRequestFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgePathSwitchRequestFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPrivateIEID(v *s20.PrivateIEID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPrivateMessage(v *s26.PrivateMessage, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationProSeAuthorized(v *s20.ProSeAuthorized, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.ProSeAuthorizedExtIEs().ProSeUEtoNetworkRelaying().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeProSeAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRATRestrictions(v *s20.RATRestrictions, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationRATRestrictionsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationRATRestrictionsItem(v *s20.RATRestrictionsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRATRestrictionsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRIMRoutingAddress(v *s34.RIMRoutingAddress, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.RIMRoutingAddressChoiceGERANCellID && v.GERANCellID != nil {
		BridgeWalkValidationGERANCellID(v.GERANCellID, report, path+".gERAN-Cell-ID", false)
	}
	if v.Choice == s00.RIMRoutingAddressChoiceTargetRNCID && v.TargetRNCID != nil {
		BridgeWalkValidationTargetRNCID(v.TargetRNCID, report, path+".targetRNC-ID", false)
	}
}
func BridgeWalkValidationRIMTransfer(v *s34.RIMTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.RIMRoutingAddress != nil {
		BridgeWalkValidationRIMRoutingAddress(v.RIMRoutingAddress, report, path+".rIMRoutingAddress", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRIMTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRLFReportInformation(v *s20.RLFReportInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.RLFReportInformationExtIEs().NBIoTRLFReportContainer().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRLFReportInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRecommendedCellItem(v *s26.RecommendedCellItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.EUTRANCGI, report, path+".eUTRAN-CGI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRecommendedCellsForPagingItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRecommendedCellList(v *s26.RecommendedCellList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s26.RecommendedCellItemIEs().RecommendedCellItem().Info()}
		s26.BridgeMergeNestedValidation(report, s28.BridgeRecommendedCellItemIEValueValidateS1APIEContainer(s26.RecommendedCellItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s26.RecommendedCellItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(214):
				if value, ok := fields[i].Value.AsRecommendedCellItem(); ok {
					BridgeWalkValidationRecommendedCellItem(value, report, fmt.Sprintf("%s[%d]{id=214}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationRecommendedCellsForPaging(v *s26.RecommendedCellsForPaging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedCellList(&v.RecommendedCellList, report, path+".recommendedCellList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRecommendedCellsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRecommendedENBItem(v *s32.RecommendedENBItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMMEPagingTarget(&v.MMEPagingTarget, report, path+".mMEPagingTarget", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRecommendedENBItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRecommendedENBList(v *s32.RecommendedENBList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s32.RecommendedENBItemIEs().RecommendedENBItem().Info()}
		s26.BridgeMergeNestedValidation(report, s34.BridgeRecommendedENBItemIEValueValidateS1APIEContainer(s32.RecommendedENBItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s32.RecommendedENBItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(215):
				if value, ok := fields[i].Value.AsRecommendedENBItem(); ok {
					BridgeWalkValidationRecommendedENBItem(value, report, fmt.Sprintf("%s[%d]{id=215}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationRecommendedENBsForPaging(v *s33.RecommendedENBsForPaging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedENBList(&v.RecommendedENBList, report, path+".recommendedENBList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRecommendedENBsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationReportingCellList(v *s20.ReportingCellList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationReportingCellListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationReportingCellListItem(v *s20.ReportingCellListItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationIRATCellID(&v.CellID, report, path+".cell-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRequestType(v *s26.RequestType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.RequestTypeExtIEs().RequestTypeAdditionalInfo().Info())}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRequestTypeExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRequestedCellList(v *s20.RequestedCellList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationIRATCellID(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationRequestedTNLInfo(v *s26.RequestedTNLInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeRequestedTNLInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRerouteNASRequest(v *s27.RerouteNASRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s20.RerouteNASRequestIEs().ENBUES1APID().Info(), s20.RerouteNASRequestIEs().MMEUES1APID().Info(), s20.RerouteNASRequestIEs().S1Message().Info(), s20.RerouteNASRequestIEs().MMEGroupID().Info(), s20.RerouteNASRequestIEs().AdditionalGUTI().Info(), s20.RerouteNASRequestIEs().UEUsageType().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeRerouteNASRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(224):
				if value, ok := fields[i].Value.AsAdditionalGUTI(); ok {
					BridgeWalkValidationAdditionalGUTI(value, report, fmt.Sprintf("%s[%d]{id=224}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRetrieveUEInformation(v *s28.RetrieveUEInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s28.RetrieveUEInformationIEs().STMSI().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeRetrieveUEInformationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1RemovalFailure(v *s27.S1RemovalFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.S1RemovalFailureIEs().Cause().Info(), s23.S1RemovalFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeS1RemovalFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1RemovalRequest(v *s27.S1RemovalRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s20.S1RemovalRequestIEs().GlobalENBID().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeS1RemovalRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1RemovalResponse(v *s27.S1RemovalResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.S1RemovalResponseIEs().MMEname().Info(), s23.S1RemovalResponseIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeS1RemovalResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1SetupFailure(v *s27.S1SetupFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.S1SetupFailureIEs().Cause().Info(), s23.S1SetupFailureIEs().TimeToWait().Info(), s23.S1SetupFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s28.BridgeS1SetupFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1SetupRequest(v *s44.S1SetupRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.S1SetupRequestIEs().GlobalENBID().Info(), s44.S1SetupRequestIEs().ENBname().Info(), s44.S1SetupRequestIEs().SupportedTAs().Info(), s44.S1SetupRequestIEs().DefaultPagingDRX().Info(), s44.S1SetupRequestIEs().CSGIdList().Info(), s44.S1SetupRequestIEs().UERetentionInformation().Info(), s44.S1SetupRequestIEs().NBIoTDefaultPagingDRX().Info(), s44.S1SetupRequestIEs().ConnectedengNBList().Info()}
			s26.BridgeMergeNestedValidation(report, s44.BridgeS1SetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(64):
				if value, ok := fields[i].Value.AsSupportedTAs(); ok {
					BridgeWalkValidationSupportedTAs(value, report, fmt.Sprintf("%s[%d]{id=64}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(291):
				if value, ok := fields[i].Value.AsConnectedengNBList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=291}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1SetupResponse(v *s44.S1SetupResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.S1SetupResponseIEs().MMEname().Info(), s44.S1SetupResponseIEs().ServedGUMMEIs().Info(), s44.S1SetupResponseIEs().RelativeMMECapacity().Info(), s44.S1SetupResponseIEs().MMERelaySupportIndicator().Info(), s44.S1SetupResponseIEs().CriticalityDiagnostics().Info(), s44.S1SetupResponseIEs().UERetentionInformation().Info(), s44.S1SetupResponseIEs().ServedDCNs().Info(), s44.S1SetupResponseIEs().IABSupported().Info()}
			s26.BridgeMergeNestedValidation(report, s44.BridgeS1SetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(105):
				if value, ok := fields[i].Value.AsServedGUMMEIs(); ok {
					BridgeWalkValidationServedGUMMEIs(value, report, fmt.Sprintf("%s[%d]{id=105}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(247):
				if value, ok := fields[i].Value.AsServedDCNs(); ok {
					BridgeWalkValidationServedDCNs(value, report, fmt.Sprintf("%s[%d]{id=247}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONInformationExtension(v *s20.SONInformationExtension, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONInformationReport(v *s20.SONInformationReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONInformationReportChoiceRLFReportInformation && v.RLFReportInformation != nil {
		BridgeWalkValidationRLFReportInformation(v.RLFReportInformation, report, path+".rLFReportInformation", false)
	}
}
func BridgeWalkValidationSONtransferCause(v *s20.SONtransferCause, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationSONtransferRequestContainer(v *s24.SONtransferRequestContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONtransferRequestContainerChoiceMultiCellLoadReporting && v.MultiCellLoadReporting != nil {
		BridgeWalkValidationMultiCellLoadReportingRequest(v.MultiCellLoadReporting, report, path+".multiCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting && v.EventTriggeredCellLoadReporting != nil {
		BridgeWalkValidationEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, report, path+".eventTriggeredCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceHOReporting && v.HOReporting != nil {
		BridgeWalkValidationHOReport(v.HOReporting, report, path+".hOReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEutranCellActivation && v.EutranCellActivation != nil {
		BridgeWalkValidationCellActivationRequest(v.EutranCellActivation, report, path+".eutranCellActivation", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEnergySavingsIndication && v.EnergySavingsIndication != nil {
		BridgeWalkValidationCellStateIndication(v.EnergySavingsIndication, report, path+".energySavingsIndication", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceFailureEventReporting && v.FailureEventReporting != nil {
		BridgeWalkValidationFailureEventReport(v.FailureEventReporting, report, path+".failureEventReporting", false)
	}
}
func BridgeWalkValidationSONtransferResponseContainer(v *s24.SONtransferResponseContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONtransferResponseContainerChoiceCellLoadReporting && v.CellLoadReporting != nil {
		BridgeWalkValidationCellLoadReportingResponse(v.CellLoadReporting, report, path+".cellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferResponseContainerChoiceMultiCellLoadReporting && v.MultiCellLoadReporting != nil {
		BridgeWalkValidationMultiCellLoadReportingResponse(&v.MultiCellLoadReporting, report, path+".multiCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting && v.EventTriggeredCellLoadReporting != nil {
		BridgeWalkValidationEventTriggeredCellLoadReportingResponse(v.EventTriggeredCellLoadReporting, report, path+".eventTriggeredCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferResponseContainerChoiceEutranCellActivation && v.EutranCellActivation != nil {
		BridgeWalkValidationCellActivationResponse(v.EutranCellActivation, report, path+".eutranCellActivation", false)
	}
}
func BridgeWalkValidationSTMSI(v *s28.STMSI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeSTMSIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationScheduledCommunicationTime(v *s28.ScheduledCommunicationTime, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeScheduledCommunicationTimeExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSecondaryRATDataUsageReportItem(v *s28.SecondaryRATDataUsageReportItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationERABUsageReportList(&v.ERABUsageReportList, report, path+".e-RABUsageReportList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s28.BridgeSecondaryRATDataUsageReportItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSecondaryRATDataUsageReportList(v *s28.SecondaryRATDataUsageReportList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s28.SecondaryRATDataUsageReportItemIEs().SecondaryRATDataUsageReportItem().Info()}
		s26.BridgeMergeNestedValidation(report, s28.BridgeSecondaryRATDataUsageReportItemIEValueValidateS1APIEContainer(s28.SecondaryRATDataUsageReportItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s28.SecondaryRATDataUsageReportItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(265):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportItem(); ok {
					BridgeWalkValidationSecondaryRATDataUsageReportItem(value, report, fmt.Sprintf("%s[%d]{id=265}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationSecurityContext(v *s29.SecurityContext, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s29.BridgeSecurityContextExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSecurityIndication(v *s29.SecurityIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s30.BridgeSecurityIndicationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSecurityResult(v *s30.SecurityResult, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s30.BridgeSecurityResultExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSensorMeasConfigNameItem(v *s31.SensorMeasConfigNameItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationSensorNameConfig(&v.SensorNameConfig, report, path+".sensorNameConfig", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s30.BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSensorMeasConfigNameList(v *s31.SensorMeasConfigNameList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSensorMeasConfigNameItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSensorMeasurementConfiguration(v *s31.SensorMeasurementConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.SensorMeasConfigNameList != nil {
		BridgeWalkValidationSensorMeasConfigNameList(&v.SensorMeasConfigNameList, report, path+".sensorMeasConfigNameList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s30.BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSensorNameConfig(v *s30.SensorNameConfig, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationServedDCNs(v *s31.ServedDCNs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationServedDCNsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationServedDCNsItem(v *s31.ServedDCNsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s31.BridgeServedDCNsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationServedGUMMEIs(v *s31.ServedGUMMEIs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationServedGUMMEIsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationServedGUMMEIsItem(v *s31.ServedGUMMEIsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationServedPLMNs(&v.ServedPLMNs, report, path+".servedPLMNs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationServedGroupIDs(&v.ServedGroupIDs, report, path+".servedGroupIDs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationServedMMECs(&v.ServedMMECs, report, path+".servedMMECs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.ServedGUMMEIsItemExtIEs().GUMMEIType().Info())}
				s26.BridgeMergeNestedValidation(report, s31.BridgeServedGUMMEIsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationServedGroupIDs(v *s00.ServedGroupIDs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationServedMMECs(v *s00.ServedMMECs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationServedPLMNs(v *s00.ServedPLMNs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationSourceNgRanNodeID(v *s31.SourceNgRanNodeID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalRANNODEID(&v.GlobalRANNODEID, report, path+".global-RAN-NODE-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationFiveGSTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s31.BridgeSourceNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSourceNodeID(v *s31.SourceNodeID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SourceNodeIDChoiceSourceNgRanNodeID && v.SourceNgRanNodeID != nil {
		BridgeWalkValidationSourceNgRanNodeID(v.SourceNgRanNodeID, report, path+".sourceNgRanNode-ID", false)
	}
	if v.Choice == s00.SourceNodeIDChoiceSourceNodeIDExtension && v.SourceNodeIDExtension != nil {
		BridgeWalkValidationSourceNodeIDExtension(v.SourceNodeIDExtension, report, path+".sourceNodeID-Extension", false)
	}
}
func BridgeWalkValidationSourceNodeIDExtension(v *s20.SourceNodeIDExtension, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSourceeNBID(v *s32.SourceeNBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalENBID(&v.GlobalENBID, report, path+".global-ENB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s31.BridgeSourceeNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(v *s31.SubscriptionBasedUEDifferentiationInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ScheduledCommunicationTime != nil {
		BridgeWalkValidationScheduledCommunicationTime(v.ScheduledCommunicationTime, report, path+".scheduledCommunicationTime", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s31.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSupportedTAs(v *s31.SupportedTAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSupportedTAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSupportedTAsItem(v *s31.SupportedTAsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationBPLMNs(&v.BroadcastPLMNs, report, path+".broadcastPLMNs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.SupportedTAsItemExtIEs().RATType().Info())}
				s26.BridgeMergeNestedValidation(report, s31.BridgeSupportedTAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSynchronisationInformation(v *s31.SynchronisationInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ListeningSubframePattern != nil {
		BridgeWalkValidationListeningSubframePattern(v.ListeningSubframePattern, report, path+".listeningSubframePattern", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AggressoreCGIList != nil {
		BridgeWalkValidationIEsECGIList(&v.AggressoreCGIList, report, path+".aggressoreCGI-List", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s31.BridgeSynchronisationInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTABasedMDT(v *s32.TABasedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAListforMDT(&v.TAListforMDT, report, path+".tAListforMDT", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s32.BridgeTABasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTABasedQMC(v *s32.TABasedQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAListforQMC(&v.TAListforQMC, report, path+".tAListforQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s32.BridgeTABasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTACListInLTENTN(v *s00.TACListInLTENTN, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTAI(v *s32.TAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s34.BridgeTAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBasedMDT(v *s33.TAIBasedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAIListforMDT(&v.TAIListforMDT, report, path+".tAIListforMDT", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s32.BridgeTAIBasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBasedQMC(v *s33.TAIBasedQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAIListforQMC(&v.TAIListforQMC, report, path+".tAIListforQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s32.BridgeTAIBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBroadcast(v *s32.TAIBroadcast, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAIBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIBroadcastItem(v *s32.TAIBroadcastItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCompletedCellinTAI(&v.CompletedCellinTAI, report, path+".completedCellinTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s32.BridgeTAIBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAICancelled(v *s32.TAICancelled, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAICancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAICancelledItem(v *s32.TAICancelledItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCancelledCellinTAI(&v.CancelledCellinTAI, report, path+".cancelledCellinTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s32.BridgeTAICancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIItem(v *s34.TAIItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s34.BridgeTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIList(v *s34.TAIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s34.TAIItemIEs().TAIItem().Info()}
		s26.BridgeMergeNestedValidation(report, s34.BridgeTAIItemIEValueValidateS1APIEContainer(s34.TAIItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s34.TAIItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(47):
				if value, ok := fields[i].Value.AsTAIItem(); ok {
					BridgeWalkValidationTAIItem(value, report, fmt.Sprintf("%s[%d]{id=47}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationTAIListForRestart(v *s32.TAIListForRestart, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforMDT(v *s32.TAIListforMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforQMC(v *s32.TAIListforQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforWarning(v *s32.TAIListforWarning, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAListforMDT(v *s00.TAListforMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTAListforQMC(v *s00.TAListforQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTargetID(v *s34.TargetID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.TargetIDChoiceTargeteNBID && v.TargeteNBID != nil {
		BridgeWalkValidationTargeteNBID(v.TargeteNBID, report, path+".targeteNB-ID", false)
	}
	if v.Choice == s00.TargetIDChoiceTargetRNCID && v.TargetRNCID != nil {
		BridgeWalkValidationTargetRNCID(v.TargetRNCID, report, path+".targetRNC-ID", false)
	}
	if v.Choice == s00.TargetIDChoiceCGI && v.CGI != nil {
		BridgeWalkValidationCGI(v.CGI, report, path+".cGI", false)
	}
	if v.Choice == s00.TargetIDChoiceTargetgNgRanNodeID && v.TargetgNgRanNodeID != nil {
		BridgeWalkValidationTargetNgRanNodeID(v.TargetgNgRanNodeID, report, path+".targetgNgRanNode-ID", false)
	}
}
func BridgeWalkValidationTargetNgRanNodeID(v *s34.TargetNgRanNodeID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalRANNODEID(&v.GlobalRANNODEID, report, path+".global-RAN-NODE-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationFiveGSTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s34.BridgeTargetNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargetRNCID(v *s34.TargetRNCID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationLAI(&v.LAI, report, path+".lAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s34.BridgeTargetRNCIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargeteNBID(v *s34.TargeteNBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalENBID(&v.GlobalENBID, report, path+".global-ENB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s35.BridgeTargeteNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargeteNBToSourceeNBTransparentContainer(v *s40.TargeteNBToSourceeNBTransparentContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s40.TargeteNBToSourceeNBTransparentContainerExtIEs().DAPSResponseInfoList().Info()), s00.FieldInfo(s40.TargeteNBToSourceeNBTransparentContainerExtIEs().RACSIndication().Info()), s00.FieldInfo(s40.TargeteNBToSourceeNBTransparentContainerExtIEs().ERABSecurityResultList().Info()), s00.FieldInfo(s40.TargeteNBToSourceeNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Info())}
				s26.BridgeMergeNestedValidation(report, s40.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(318):
					if value, ok := fields[i].ExtensionValue.AsDAPSResponseInfoList(); ok {
						BridgeWalkValidationDAPSResponseInfoList(value, report, fmt.Sprintf("%s[%d]{id=318}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(335):
					if value, ok := fields[i].ExtensionValue.AsERABSecurityResultList(); ok {
						BridgeWalkValidationERABSecurityResultList(value, report, fmt.Sprintf("%s[%d]{id=335}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTimeBasedHandoverInformation(v *s35.TimeBasedHandoverInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s35.BridgeTimeBasedHandoverInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTimeSynchronisationInfo(v *s35.TimeSynchronisationInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s12.TimeSynchronisationInfoExtIEs().MutingAvailabilityIndication().Info())}
				s26.BridgeMergeNestedValidation(report, s35.BridgeTimeSynchronisationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTooEarlyInterRATHOReportReportFromEUTRAN(v *s21.TooEarlyInterRATHOReportReportFromEUTRAN, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTraceFailureIndication(v *s35.TraceFailureIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s21.TraceFailureIndicationIEs().MMEUES1APID().Info(), s21.TraceFailureIndicationIEs().ENBUES1APID().Info(), s21.TraceFailureIndicationIEs().EUTRANTraceID().Info(), s21.TraceFailureIndicationIEs().Cause().Info()}
			s26.BridgeMergeNestedValidation(report, s35.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTransportInformation(v *s21.TransportInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTunnelInformation(v *s35.TunnelInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s36.BridgeTunnelInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAggregateMaximumBitrate(v *s36.UEAggregateMaximumBitrate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s12.UEAggregateMaximumBitratesExtIEs().ExtendedUEaggregateMaximumBitRateDL().Info()), s00.FieldInfo(s12.UEAggregateMaximumBitratesExtIEs().ExtendedUEaggregateMaximumBitRateUL().Info())}
				s26.BridgeMergeNestedValidation(report, s36.BridgeUEAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAppLayerMeasConfig(v *s36.UEAppLayerMeasConfig, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationAreaScopeOfQMC(&v.AreaScopeOfQMC, report, path+".areaScopeOfQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s12.UEAppLayerMeasConfigExtIEs().ServiceType().Info())}
				s26.BridgeMergeNestedValidation(report, s36.BridgeUEAppLayerMeasConfigExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgePagingAPERValueFieldContext(v *PagingAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgePagingAPERValueFieldReceived(v *PagingAPERValue) *aper.WireSpan         { return &v.received }
func BridgePagingAPERValueFieldReplay(v *PagingAPERValue) *aper.Snapshot           { return &v.replay }
func BridgePagingAPERValueFieldWithoutReplay(v *PagingAPERValue) *bool             { return &v.withoutReplay }
func BridgePagingAssistanceDataForPagingIEBindingFieldCodec(v *PagingAssistanceDataForPagingIEBinding) *s26.AssistanceDataForPagingValueCodec {
	return &v.codec
}
func BridgePagingAssistanceDataForPagingIEBindingFieldGet(v *PagingAssistanceDataForPagingIEBinding) *func(*PagingIEValue) (*s26.AssistanceDataForPaging, bool) {
	return &v.get
}
func BridgePagingAssistanceDataForPagingIEBindingFieldInfo(v *PagingAssistanceDataForPagingIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingAssistanceDataForPagingIEBindingFieldInject(v *PagingAssistanceDataForPagingIEBinding) *func(s26.AssistanceDataForPaging) PagingIEValue {
	return &v.inject
}
func BridgePagingCEModeBRestrictedIEBindingFieldCodec(v *PagingCEModeBRestrictedIEBinding) *s00.CEModeBRestrictedValueCodec {
	return &v.codec
}
func BridgePagingCEModeBRestrictedIEBindingFieldGet(v *PagingCEModeBRestrictedIEBinding) *func(*PagingIEValue) (*s00.CEModeBRestricted, bool) {
	return &v.get
}
func BridgePagingCEModeBRestrictedIEBindingFieldInfo(v *PagingCEModeBRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingCEModeBRestrictedIEBindingFieldInject(v *PagingCEModeBRestrictedIEBinding) *func(s00.CEModeBRestricted) PagingIEValue {
	return &v.inject
}
func BridgePagingCNDomainIEBindingFieldCodec(v *PagingCNDomainIEBinding) *s00.CNDomainValueCodec {
	return &v.codec
}
func BridgePagingCNDomainIEBindingFieldGet(v *PagingCNDomainIEBinding) *func(*PagingIEValue) (*s00.CNDomain, bool) {
	return &v.get
}
func BridgePagingCNDomainIEBindingFieldInfo(v *PagingCNDomainIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingCNDomainIEBindingFieldInject(v *PagingCNDomainIEBinding) *func(s00.CNDomain) PagingIEValue {
	return &v.inject
}
func BridgePagingCSGIdListIEBindingFieldCodec(v *PagingCSGIdListIEBinding) *s14.CSGIdListValueCodec {
	return &v.codec
}
func BridgePagingCSGIdListIEBindingFieldGet(v *PagingCSGIdListIEBinding) *func(*PagingIEValue) (*s14.CSGIdList, bool) {
	return &v.get
}
func BridgePagingCSGIdListIEBindingFieldInfo(v *PagingCSGIdListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingCSGIdListIEBindingFieldInject(v *PagingCSGIdListIEBinding) *func(s14.CSGIdList) PagingIEValue {
	return &v.inject
}
func BridgePagingDataSizeIEBindingFieldCodec(v *PagingDataSizeIEBinding) *s00.DataSizeValueCodec {
	return &v.codec
}
func BridgePagingDataSizeIEBindingFieldGet(v *PagingDataSizeIEBinding) *func(*PagingIEValue) (*s00.DataSize, bool) {
	return &v.get
}
func BridgePagingDataSizeIEBindingFieldInfo(v *PagingDataSizeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingDataSizeIEBindingFieldInject(v *PagingDataSizeIEBinding) *func(s00.DataSize) PagingIEValue {
	return &v.inject
}
func BridgePagingEnhancedCoverageRestrictedIEBindingFieldCodec(v *PagingEnhancedCoverageRestrictedIEBinding) *s00.EnhancedCoverageRestrictedValueCodec {
	return &v.codec
}
func BridgePagingEnhancedCoverageRestrictedIEBindingFieldGet(v *PagingEnhancedCoverageRestrictedIEBinding) *func(*PagingIEValue) (*s00.EnhancedCoverageRestricted, bool) {
	return &v.get
}
func BridgePagingEnhancedCoverageRestrictedIEBindingFieldInfo(v *PagingEnhancedCoverageRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingEnhancedCoverageRestrictedIEBindingFieldInject(v *PagingEnhancedCoverageRestrictedIEBinding) *func(s00.EnhancedCoverageRestricted) PagingIEValue {
	return &v.inject
}
func BridgePagingExtendedUEIdentityIndexValueIEBindingFieldCodec(v *PagingExtendedUEIdentityIndexValueIEBinding) *s00.ExtendedUEIdentityIndexValueValueCodec {
	return &v.codec
}
func BridgePagingExtendedUEIdentityIndexValueIEBindingFieldGet(v *PagingExtendedUEIdentityIndexValueIEBinding) *func(*PagingIEValue) (*s00.ExtendedUEIdentityIndexValue, bool) {
	return &v.get
}
func BridgePagingExtendedUEIdentityIndexValueIEBindingFieldInfo(v *PagingExtendedUEIdentityIndexValueIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingExtendedUEIdentityIndexValueIEBindingFieldInject(v *PagingExtendedUEIdentityIndexValueIEBinding) *func(s00.ExtendedUEIdentityIndexValue) PagingIEValue {
	return &v.inject
}
func BridgePagingFieldExtCount(v *Paging) *int64                       { return &v.extCount }
func BridgePagingFieldExtData(v *Paging) *[][]byte                     { return &v.extData }
func BridgePagingFieldExtOrigin(v *Paging) *[]aper.OpaqueOrigin        { return &v.extOrigin }
func BridgePagingFieldExtPresent(v *Paging) *[]bool                    { return &v.extPresent }
func BridgePagingFieldExtWire(v *Paging) *[]aper.WireSpan              { return &v.extWire }
func BridgePagingFieldPerExtPadding(v *Paging) *[]aper.CompletePadding { return &v.perExtPadding }
func BridgePagingFieldPerPadding(v *Paging) *aper.FinalPadding         { return &v.perPadding }
func BridgePagingFieldProtocolIEsIndef(v *Paging) *bool                { return &v.protocolIEsIndef }
func BridgePagingFieldReceived(v *Paging) *bool                        { return &v.received }
func BridgePagingFieldReceivedAbsolute(v *Paging) *bool                { return &v.receivedAbsolute }
func BridgePagingFieldReceivedBytes(v *Paging) *aper.WireSpan          { return &v.receivedBytes }
func BridgePagingFieldReceivedLocation(v *Paging) *aper.Location       { return &v.receivedLocation }
func BridgePagingFieldReplay(v *Paging) *aper.Snapshot                 { return &v.replay }
func BridgePagingFieldStream(v *Paging) *aper.WireSpan                 { return &v.stream }
func BridgePagingFieldWithoutReplay(v *Paging) *bool                   { return &v.withoutReplay }
func BridgePagingIEContainerAPERValueFieldContext(v *PagingIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEContainerAPERValueFieldReceived(v *PagingIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingIEContainerAPERValueFieldReplay(v *PagingIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingIEContainerAPERValueFieldWithoutReplay(v *PagingIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingIEContainerValueCodecFieldCapture(v *PagingIEContainerValueCodec) *func(PagingIEContainer, aper.DecodeState) (PagingIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePagingIEContainerValueCodecFieldCompare(v *PagingIEContainerValueCodec) *func(PagingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingIEContainerValueCodecFieldContext(v *PagingIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEContainerValueCodecFieldDecode(v *PagingIEContainerValueCodec) *func([]byte, aper.DecodeState) (PagingIEContainer, error) {
	return &v.decode
}
func BridgePagingIEContainerValueCodecFieldEncode(v *PagingIEContainerValueCodec) *func(PagingIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingIEContainerValueCodecFieldPath(v *PagingIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingIEContainerValueCodecMethodEncodeBudgetValue(v PagingIEContainerValueCodec, a0 PagingIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingIEContainerValueCodecMethodEncodeChanged(v PagingIEContainerValueCodec, a0 PagingIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingIEFieldAPERValueFieldContext(v *PagingIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEFieldAPERValueFieldReceived(v *PagingIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingIEFieldAPERValueFieldReplay(v *PagingIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingIEFieldAPERValueFieldWithoutReplay(v *PagingIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingIEFieldFieldReceived(v *PagingIEField) *aper.CompletePadding { return &v.received }
func BridgePagingIEFieldFieldReplay(v *PagingIEField) *aper.Snapshot          { return &v.replay }
func BridgePagingIEFieldFieldStream(v *PagingIEField) *aper.WireSpan          { return &v.stream }
func BridgePagingIEFieldFieldWithoutReplay(v *PagingIEField) *bool            { return &v.withoutReplay }
func BridgePagingIEFieldMethodMarshalAPERTo(v *PagingIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePagingIEFieldMethodUnmarshalAPERFrom(v *PagingIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingIEFieldValueCodecFieldCapture(v *PagingIEFieldValueCodec) *func(PagingIEField, aper.DecodeState) (PagingIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePagingIEFieldValueCodecFieldCompare(v *PagingIEFieldValueCodec) *func(PagingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingIEFieldValueCodecFieldContext(v *PagingIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEFieldValueCodecFieldDecode(v *PagingIEFieldValueCodec) *func([]byte, aper.DecodeState) (PagingIEField, error) {
	return &v.decode
}
func BridgePagingIEFieldValueCodecFieldEncode(v *PagingIEFieldValueCodec) *func(PagingIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingIEFieldValueCodecFieldPath(v *PagingIEFieldValueCodec) *aper.Path { return &v.path }
func BridgePagingIEFieldValueCodecMethodEncodeBudgetValue(v PagingIEFieldValueCodec, a0 PagingIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingIEFieldValueCodecMethodEncodeChanged(v PagingIEFieldValueCodec, a0 PagingIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingIETableMethodInfoAssistanceDataForPaging(v PagingIETable) s00.FieldInfo {
	return v.infoAssistanceDataForPaging()
}
func BridgePagingIETableMethodInfoCEModeBRestricted(v PagingIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgePagingIETableMethodInfoCNDomain(v PagingIETable) s00.FieldInfo  { return v.infoCNDomain() }
func BridgePagingIETableMethodInfoCSGIdList(v PagingIETable) s00.FieldInfo { return v.infoCSGIdList() }
func BridgePagingIETableMethodInfoDataSize(v PagingIETable) s00.FieldInfo  { return v.infoDataSize() }
func BridgePagingIETableMethodInfoEnhancedCoverageRestricted(v PagingIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgePagingIETableMethodInfoExtendedUEIdentityIndexValue(v PagingIETable) s00.FieldInfo {
	return v.infoExtendedUEIdentityIndexValue()
}
func BridgePagingIETableMethodInfoNBIoTPagingDRX(v PagingIETable) s00.FieldInfo {
	return v.infoNBIoTPagingDRX()
}
func BridgePagingIETableMethodInfoNBIoTPagingEDRXInformation(v PagingIETable) s00.FieldInfo {
	return v.infoNBIoTPagingEDRXInformation()
}
func BridgePagingIETableMethodInfoNBIoTUEIdentityIndexValue(v PagingIETable) s00.FieldInfo {
	return v.infoNBIoTUEIdentityIndexValue()
}
func BridgePagingIETableMethodInfoPagingCause(v PagingIETable) s00.FieldInfo {
	return v.infoPagingCause()
}
func BridgePagingIETableMethodInfoPagingDRX(v PagingIETable) s00.FieldInfo { return v.infoPagingDRX() }
func BridgePagingIETableMethodInfoPagingEDRXInformation(v PagingIETable) s00.FieldInfo {
	return v.infoPagingEDRXInformation()
}
func BridgePagingIETableMethodInfoPagingPriority(v PagingIETable) s00.FieldInfo {
	return v.infoPagingPriority()
}
func BridgePagingIETableMethodInfoTAIList(v PagingIETable) s00.FieldInfo { return v.infoTAIList() }
func BridgePagingIETableMethodInfoUEIdentityIndexValue(v PagingIETable) s00.FieldInfo {
	return v.infoUEIdentityIndexValue()
}
func BridgePagingIETableMethodInfoUEPagingID(v PagingIETable) s00.FieldInfo {
	return v.infoUEPagingID()
}
func BridgePagingIETableMethodInfoUERadioCapabilityForPaging(v PagingIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityForPaging()
}
func BridgePagingIETableMethodInfoWUSAssistanceInformation(v PagingIETable) s00.FieldInfo {
	return v.infoWUSAssistanceInformation()
}
func BridgePagingIEValueERABIEContainerListAPERValueFieldContext(v *PagingIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEValueERABIEContainerListAPERValueFieldReceived(v *PagingIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingIEValueERABIEContainerListAPERValueFieldReplay(v *PagingIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PagingIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingIEValueERABIEContainerListValueCodecFieldCapture(v *PagingIEValueERABIEContainerListValueCodec) *func(PagingIEValueERABIEContainerList, aper.DecodeState) (PagingIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePagingIEValueERABIEContainerListValueCodecFieldCompare(v *PagingIEValueERABIEContainerListValueCodec) *func(PagingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingIEValueERABIEContainerListValueCodecFieldContext(v *PagingIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEValueERABIEContainerListValueCodecFieldDecode(v *PagingIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PagingIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePagingIEValueERABIEContainerListValueCodecFieldEncode(v *PagingIEValueERABIEContainerListValueCodec) *func(PagingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingIEValueERABIEContainerListValueCodecFieldPath(v *PagingIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PagingIEValueERABIEContainerListValueCodec, a0 PagingIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PagingIEValueERABIEContainerListValueCodec, a0 PagingIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingIEValueFieldId(v *PagingIEValue) *s00.ProtocolIEID        { return &v.id }
func BridgePagingIEValueFieldIsOpaque(v *PagingIEValue) *bool              { return &v.isOpaque }
func BridgePagingIEValueFieldOpaque(v *PagingIEValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgePagingIEValueFieldReceived(v *PagingIEValue) *aper.WireSpan     { return &v.received }
func BridgePagingIEValueFieldReplay(v *PagingIEValue) *aper.Snapshot       { return &v.replay }
func BridgePagingIEValueFieldRowAssistanceDataForPaging(v *PagingIEValue) **s26.AssistanceDataForPaging {
	return &v.rowAssistanceDataForPaging
}
func BridgePagingIEValueFieldRowCEModeBRestricted(v *PagingIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgePagingIEValueFieldRowCNDomain(v *PagingIEValue) **s00.CNDomain   { return &v.rowCNDomain }
func BridgePagingIEValueFieldRowCSGIdList(v *PagingIEValue) **s14.CSGIdList { return &v.rowCSGIdList }
func BridgePagingIEValueFieldRowDataSize(v *PagingIEValue) **s00.DataSize   { return &v.rowDataSize }
func BridgePagingIEValueFieldRowEnhancedCoverageRestricted(v *PagingIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgePagingIEValueFieldRowExtendedUEIdentityIndexValue(v *PagingIEValue) **s00.ExtendedUEIdentityIndexValue {
	return &v.rowExtendedUEIdentityIndexValue
}
func BridgePagingIEValueFieldRowNBIoTPagingDRX(v *PagingIEValue) **s00.NBIoTPagingDRX {
	return &v.rowNBIoTPagingDRX
}
func BridgePagingIEValueFieldRowNBIoTPagingEDRXInformation(v *PagingIEValue) **s19.NBIoTPagingEDRXInformation {
	return &v.rowNBIoTPagingEDRXInformation
}
func BridgePagingIEValueFieldRowNBIoTUEIdentityIndexValue(v *PagingIEValue) **s00.NBIoTUEIdentityIndexValue {
	return &v.rowNBIoTUEIdentityIndexValue
}
func BridgePagingIEValueFieldRowPagingCause(v *PagingIEValue) **s00.PagingCause {
	return &v.rowPagingCause
}
func BridgePagingIEValueFieldRowPagingDRX(v *PagingIEValue) **s00.PagingDRX { return &v.rowPagingDRX }
func BridgePagingIEValueFieldRowPagingEDRXInformation(v *PagingIEValue) **s20.PagingEDRXInformation {
	return &v.rowPagingEDRXInformation
}
func BridgePagingIEValueFieldRowPagingPriority(v *PagingIEValue) **s00.PagingPriority {
	return &v.rowPagingPriority
}
func BridgePagingIEValueFieldRowTAIList(v *PagingIEValue) **s34.TAIList { return &v.rowTAIList }
func BridgePagingIEValueFieldRowUEIdentityIndexValue(v *PagingIEValue) **s00.UEIdentityIndexValue {
	return &v.rowUEIdentityIndexValue
}
func BridgePagingIEValueFieldRowUEPagingID(v *PagingIEValue) **s28.UEPagingID {
	return &v.rowUEPagingID
}
func BridgePagingIEValueFieldRowUERadioCapabilityForPaging(v *PagingIEValue) **s00.UERadioCapabilityForPaging {
	return &v.rowUERadioCapabilityForPaging
}
func BridgePagingIEValueFieldRowWUSAssistanceInformation(v *PagingIEValue) **s49.WUSAssistanceInformation {
	return &v.rowWUSAssistanceInformation
}
func BridgePagingIEValueMethodCaptureSemantics(v PagingIEValue, a0 aper.SemanticCapture) PagingIEValue {
	return v.captureSemantics(a0)
}
func BridgePagingIEValueMethodCompareSemantics(v PagingIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePagingIEValueMethodDecode(v PagingIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PagingIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePagingIEValueMethodEncode(v PagingIEValue) ([]byte, error) { return v.encode() }
func BridgePagingIEValueMethodEncodeFresh(v PagingIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePagingIEValueMethodMatchesID(v PagingIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePagingIEValueMethodReason(v PagingIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePagingIEValueMethodRule(v PagingIEValue) aper.SourceRule { return v.rule() }
func BridgePagingIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PagingIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PagingIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PagingIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PagingIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PagingIEValueProtocolErrorIEContainerListValueCodec) *func(PagingIEValueProtocolErrorIEContainerList, aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PagingIEValueProtocolErrorIEContainerListValueCodec) *func(PagingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PagingIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PagingIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PagingIEValueProtocolErrorIEContainerListValueCodec) *func(PagingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PagingIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PagingIEValueProtocolErrorIEContainerListValueCodec, a0 PagingIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PagingIEValueProtocolErrorIEContainerListValueCodec, a0 PagingIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingIEValueProtocolIEContainerListAPERValueFieldContext(v *PagingIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEValueProtocolIEContainerListAPERValueFieldReceived(v *PagingIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingIEValueProtocolIEContainerListAPERValueFieldReplay(v *PagingIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PagingIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingIEValueProtocolIEContainerListValueCodecFieldCapture(v *PagingIEValueProtocolIEContainerListValueCodec) *func(PagingIEValueProtocolIEContainerList, aper.DecodeState) (PagingIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePagingIEValueProtocolIEContainerListValueCodecFieldCompare(v *PagingIEValueProtocolIEContainerListValueCodec) *func(PagingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingIEValueProtocolIEContainerListValueCodecFieldContext(v *PagingIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingIEValueProtocolIEContainerListValueCodecFieldDecode(v *PagingIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PagingIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePagingIEValueProtocolIEContainerListValueCodecFieldEncode(v *PagingIEValueProtocolIEContainerListValueCodec) *func(PagingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingIEValueProtocolIEContainerListValueCodecFieldPath(v *PagingIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PagingIEValueProtocolIEContainerListValueCodec, a0 PagingIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PagingIEValueProtocolIEContainerListValueCodec, a0 PagingIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingMethodMarshalAPERBudget(v *Paging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePagingMethodMarshalAPERBudgetValue(v *Paging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePagingMethodMarshalAPERChanged(v *Paging, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePagingMethodMarshalAPERChangedValue(v *Paging, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePagingMethodMarshalAPERLegacy(v *Paging) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgePagingMethodMarshalAPERNewValue(v *Paging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePagingMethodMarshalAPERPlanned(v *Paging, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePagingMethodMarshalAPERTo(v *Paging, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePagingMethodUnmarshalAPERFrom(v *Paging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingMethodUnmarshalAPERLegacy(v *Paging, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePagingMethodUnmarshalAPERWithOptions(v *Paging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePagingNBIoTPagingDRXIEBindingFieldCodec(v *PagingNBIoTPagingDRXIEBinding) *s01.NBIoTPagingDRXValueCodec {
	return &v.codec
}
func BridgePagingNBIoTPagingDRXIEBindingFieldGet(v *PagingNBIoTPagingDRXIEBinding) *func(*PagingIEValue) (*s00.NBIoTPagingDRX, bool) {
	return &v.get
}
func BridgePagingNBIoTPagingDRXIEBindingFieldInfo(v *PagingNBIoTPagingDRXIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingNBIoTPagingDRXIEBindingFieldInject(v *PagingNBIoTPagingDRXIEBinding) *func(s00.NBIoTPagingDRX) PagingIEValue {
	return &v.inject
}
func BridgePagingNBIoTPagingEDRXInformationIEBindingFieldCodec(v *PagingNBIoTPagingEDRXInformationIEBinding) *s19.NBIoTPagingEDRXInformationValueCodec {
	return &v.codec
}
func BridgePagingNBIoTPagingEDRXInformationIEBindingFieldGet(v *PagingNBIoTPagingEDRXInformationIEBinding) *func(*PagingIEValue) (*s19.NBIoTPagingEDRXInformation, bool) {
	return &v.get
}
func BridgePagingNBIoTPagingEDRXInformationIEBindingFieldInfo(v *PagingNBIoTPagingEDRXInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingNBIoTPagingEDRXInformationIEBindingFieldInject(v *PagingNBIoTPagingEDRXInformationIEBinding) *func(s19.NBIoTPagingEDRXInformation) PagingIEValue {
	return &v.inject
}
func BridgePagingNBIoTUEIdentityIndexValueIEBindingFieldCodec(v *PagingNBIoTUEIdentityIndexValueIEBinding) *s01.NBIoTUEIdentityIndexValueValueCodec {
	return &v.codec
}
func BridgePagingNBIoTUEIdentityIndexValueIEBindingFieldGet(v *PagingNBIoTUEIdentityIndexValueIEBinding) *func(*PagingIEValue) (*s00.NBIoTUEIdentityIndexValue, bool) {
	return &v.get
}
func BridgePagingNBIoTUEIdentityIndexValueIEBindingFieldInfo(v *PagingNBIoTUEIdentityIndexValueIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingNBIoTUEIdentityIndexValueIEBindingFieldInject(v *PagingNBIoTUEIdentityIndexValueIEBinding) *func(s00.NBIoTUEIdentityIndexValue) PagingIEValue {
	return &v.inject
}
func BridgePagingPagingCauseIEBindingFieldCodec(v *PagingPagingCauseIEBinding) *s01.PagingCauseValueCodec {
	return &v.codec
}
func BridgePagingPagingCauseIEBindingFieldGet(v *PagingPagingCauseIEBinding) *func(*PagingIEValue) (*s00.PagingCause, bool) {
	return &v.get
}
func BridgePagingPagingCauseIEBindingFieldInfo(v *PagingPagingCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingPagingCauseIEBindingFieldInject(v *PagingPagingCauseIEBinding) *func(s00.PagingCause) PagingIEValue {
	return &v.inject
}
func BridgePagingPagingDRXIEBindingFieldCodec(v *PagingPagingDRXIEBinding) *s01.PagingDRXValueCodec {
	return &v.codec
}
func BridgePagingPagingDRXIEBindingFieldGet(v *PagingPagingDRXIEBinding) *func(*PagingIEValue) (*s00.PagingDRX, bool) {
	return &v.get
}
func BridgePagingPagingDRXIEBindingFieldInfo(v *PagingPagingDRXIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingPagingDRXIEBindingFieldInject(v *PagingPagingDRXIEBinding) *func(s00.PagingDRX) PagingIEValue {
	return &v.inject
}
func BridgePagingPagingEDRXInformationIEBindingFieldCodec(v *PagingPagingEDRXInformationIEBinding) *s20.PagingEDRXInformationValueCodec {
	return &v.codec
}
func BridgePagingPagingEDRXInformationIEBindingFieldGet(v *PagingPagingEDRXInformationIEBinding) *func(*PagingIEValue) (*s20.PagingEDRXInformation, bool) {
	return &v.get
}
func BridgePagingPagingEDRXInformationIEBindingFieldInfo(v *PagingPagingEDRXInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingPagingEDRXInformationIEBindingFieldInject(v *PagingPagingEDRXInformationIEBinding) *func(s20.PagingEDRXInformation) PagingIEValue {
	return &v.inject
}
func BridgePagingPagingPriorityIEBindingFieldCodec(v *PagingPagingPriorityIEBinding) *s01.PagingPriorityValueCodec {
	return &v.codec
}
func BridgePagingPagingPriorityIEBindingFieldGet(v *PagingPagingPriorityIEBinding) *func(*PagingIEValue) (*s00.PagingPriority, bool) {
	return &v.get
}
func BridgePagingPagingPriorityIEBindingFieldInfo(v *PagingPagingPriorityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingPagingPriorityIEBindingFieldInject(v *PagingPagingPriorityIEBinding) *func(s00.PagingPriority) PagingIEValue {
	return &v.inject
}
func BridgePagingTAIListIEBindingFieldCodec(v *PagingTAIListIEBinding) *s34.TAIListValueCodec {
	return &v.codec
}
func BridgePagingTAIListIEBindingFieldGet(v *PagingTAIListIEBinding) *func(*PagingIEValue) (*s34.TAIList, bool) {
	return &v.get
}
func BridgePagingTAIListIEBindingFieldInfo(v *PagingTAIListIEBinding) *s00.FieldInfo { return &v.info }
func BridgePagingTAIListIEBindingFieldInject(v *PagingTAIListIEBinding) *func(s34.TAIList) PagingIEValue {
	return &v.inject
}
func BridgePagingUEIdentityIndexValueIEBindingFieldCodec(v *PagingUEIdentityIndexValueIEBinding) *s02.UEIdentityIndexValueValueCodec {
	return &v.codec
}
func BridgePagingUEIdentityIndexValueIEBindingFieldGet(v *PagingUEIdentityIndexValueIEBinding) *func(*PagingIEValue) (*s00.UEIdentityIndexValue, bool) {
	return &v.get
}
func BridgePagingUEIdentityIndexValueIEBindingFieldInfo(v *PagingUEIdentityIndexValueIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingUEIdentityIndexValueIEBindingFieldInject(v *PagingUEIdentityIndexValueIEBinding) *func(s00.UEIdentityIndexValue) PagingIEValue {
	return &v.inject
}
func BridgePagingUEPagingIDIEBindingFieldCodec(v *PagingUEPagingIDIEBinding) *s28.UEPagingIDValueCodec {
	return &v.codec
}
func BridgePagingUEPagingIDIEBindingFieldGet(v *PagingUEPagingIDIEBinding) *func(*PagingIEValue) (*s28.UEPagingID, bool) {
	return &v.get
}
func BridgePagingUEPagingIDIEBindingFieldInfo(v *PagingUEPagingIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingUEPagingIDIEBindingFieldInject(v *PagingUEPagingIDIEBinding) *func(s28.UEPagingID) PagingIEValue {
	return &v.inject
}
func BridgePagingUERadioCapabilityForPagingIEBindingFieldCodec(v *PagingUERadioCapabilityForPagingIEBinding) *s02.UERadioCapabilityForPagingValueCodec {
	return &v.codec
}
func BridgePagingUERadioCapabilityForPagingIEBindingFieldGet(v *PagingUERadioCapabilityForPagingIEBinding) *func(*PagingIEValue) (*s00.UERadioCapabilityForPaging, bool) {
	return &v.get
}
func BridgePagingUERadioCapabilityForPagingIEBindingFieldInfo(v *PagingUERadioCapabilityForPagingIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingUERadioCapabilityForPagingIEBindingFieldInject(v *PagingUERadioCapabilityForPagingIEBinding) *func(s00.UERadioCapabilityForPaging) PagingIEValue {
	return &v.inject
}
func BridgePagingValueCodecFieldCapture(v *PagingValueCodec) *func(Paging, aper.DecodeState) (Paging, aper.Snapshot) {
	return &v.capture
}
func BridgePagingValueCodecFieldCompare(v *PagingValueCodec) *func(Paging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingValueCodecFieldContext(v *PagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingValueCodecFieldDecode(v *PagingValueCodec) *func([]byte, aper.DecodeState) (Paging, error) {
	return &v.decode
}
func BridgePagingValueCodecFieldEncode(v *PagingValueCodec) *func(Paging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingValueCodecFieldPath(v *PagingValueCodec) *aper.Path { return &v.path }
func BridgePagingValueCodecMethodEncodeBudgetValue(v PagingValueCodec, a0 Paging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingValueCodecMethodEncodeChanged(v PagingValueCodec, a0 Paging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingWUSAssistanceInformationIEBindingFieldCodec(v *PagingWUSAssistanceInformationIEBinding) *WUSAssistanceInformationValueCodec {
	return &v.codec
}
func BridgePagingWUSAssistanceInformationIEBindingFieldGet(v *PagingWUSAssistanceInformationIEBinding) *func(*PagingIEValue) (*s49.WUSAssistanceInformation, bool) {
	return &v.get
}
func BridgePagingWUSAssistanceInformationIEBindingFieldInfo(v *PagingWUSAssistanceInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePagingWUSAssistanceInformationIEBindingFieldInject(v *PagingWUSAssistanceInformationIEBinding) *func(s49.WUSAssistanceInformation) PagingIEValue {
	return &v.inject
}
func BridgeWUSAssistanceInformationAPERValueFieldContext(v *WUSAssistanceInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWUSAssistanceInformationAPERValueFieldReceived(v *WUSAssistanceInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWUSAssistanceInformationAPERValueFieldReplay(v *WUSAssistanceInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWUSAssistanceInformationAPERValueFieldWithoutReplay(v *WUSAssistanceInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWUSAssistanceInformationValueCodecFieldCapture(v *WUSAssistanceInformationValueCodec) *func(s49.WUSAssistanceInformation, aper.DecodeState) (s49.WUSAssistanceInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeWUSAssistanceInformationValueCodecFieldCompare(v *WUSAssistanceInformationValueCodec) *func(s49.WUSAssistanceInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWUSAssistanceInformationValueCodecFieldContext(v *WUSAssistanceInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWUSAssistanceInformationValueCodecFieldDecode(v *WUSAssistanceInformationValueCodec) *func([]byte, aper.DecodeState) (s49.WUSAssistanceInformation, error) {
	return &v.decode
}
func BridgeWUSAssistanceInformationValueCodecFieldEncode(v *WUSAssistanceInformationValueCodec) *func(s49.WUSAssistanceInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWUSAssistanceInformationValueCodecFieldPath(v *WUSAssistanceInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeWUSAssistanceInformationValueCodecMethodEncodeBudgetValue(v WUSAssistanceInformationValueCodec, a0 s49.WUSAssistanceInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWUSAssistanceInformationValueCodecMethodEncodeChanged(v WUSAssistanceInformationValueCodec, a0 s49.WUSAssistanceInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *PagingIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 80:
		if value, ok := v.AsUEIdentityIndexValue(); ok {
			return value, true
		}
	case 43:
		if value, ok := v.AsUEPagingID(); ok {
			return value, true
		}
	case 44:
		if value, ok := v.AsPagingDRX(); ok {
			return value, true
		}
	case 109:
		if value, ok := v.AsCNDomain(); ok {
			return value, true
		}
	case 46:
		if value, ok := v.AsTAIList(); ok {
			return value, true
		}
	case 128:
		if value, ok := v.AsCSGIdList(); ok {
			return value, true
		}
	case 151:
		if value, ok := v.AsPagingPriority(); ok {
			return value, true
		}
	case 198:
		if value, ok := v.AsUERadioCapabilityForPaging(); ok {
			return value, true
		}
	case 211:
		if value, ok := v.AsAssistanceDataForPaging(); ok {
			return value, true
		}
	case 227:
		if value, ok := v.AsPagingEDRXInformation(); ok {
			return value, true
		}
	case 231:
		if value, ok := v.AsExtendedUEIdentityIndexValue(); ok {
			return value, true
		}
	case 239:
		if value, ok := v.AsNBIoTPagingEDRXInformation(); ok {
			return value, true
		}
	case 244:
		if value, ok := v.AsNBIoTUEIdentityIndexValue(); ok {
			return value, true
		}
	case 251:
		if value, ok := v.AsEnhancedCoverageRestricted(); ok {
			return value, true
		}
	case 271:
		if value, ok := v.AsCEModeBRestricted(); ok {
			return value, true
		}
	case 304:
		if value, ok := v.AsDataSize(); ok {
			return value, true
		}
	case 323:
		if value, ok := v.AsWUSAssistanceInformation(); ok {
			return value, true
		}
	case 324:
		if value, ok := v.AsNBIoTPagingDRX(); ok {
			return value, true
		}
	case 331:
		if value, ok := v.AsPagingCause(); ok {
			return value, true
		}
	}
	return nil, false
}
